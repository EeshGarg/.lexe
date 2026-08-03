// `lexe apps` tests (DX4): the installed-application manager. Build + install a
// package through the CLI (into an isolated LEXE_HOME), then check the rich
// listing (version, disk, trust, last run) in human and --json form.

#include <doctest/doctest.h>

#include "elf_builder.hpp"
#include "helpers.hpp"

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

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

// Build + install a signed package into the current LEXE_HOME. Returns the id.
std::string install_app(const fs::path& work) {
    fs::create_directories(work / "proj" / "payload" / "bin");
    test::ElfSpec app;
    app.interp = "/lib64/ld-linux-x86-64.so.2";
    app.e_machine = 62;
    app.needed = {"libc.so.6"};
    app.version_needs = {"GLIBC_2.17"};
    test::write_elf(work / "proj" / "payload" / "bin" / "app", app);
    util::spit(work / "proj" / "lexe.json", std::string_view(R"({
  "lexeVersion":"0.1","id":"com.example.manageme","name":"Manage Me",
  "version":"3.4.5","publisher":{"name":"Acme Publisher","publicKey":"AUTO"},
  "applicationType":"native","architectures":["x86_64"],
  "entrypoint":{"executable":"bin/app","arguments":[]},
  "install":{"scope":"user","mode":"bundled"},"permissions":[]
})"));
    REQUIRE(run({"keygen", (work / "k.json").string()}).exit_code == 0);
    REQUIRE(run({"build", (work / "proj").string(), "-o",
                 (work / "app.lexe").string(), "--key",
                 (work / "k.json").string()})
                .exit_code == 0);
    REQUIRE(run({"install", (work / "app.lexe").string(), "--yes", "--trust"})
                .exit_code == 0);
    return "com.example.manageme";
}

} // namespace

TEST_SUITE("cli_apps") {

TEST_CASE("apps lists an installed application with rich detail") {
    test::TempLexeHome home; // isolates LEXE_HOME; child lexe inherits it
    const fs::path work = test::unique_temp_dir("lexe-apps-");
    fs::create_directories(work);
    const std::string id = install_app(work);

    const util::ProcessResult r = run({"apps"});
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "Manage Me"));
    CHECK(has(r.stdout_text, id));
    CHECK(has(r.stdout_text, "Acme Publisher"));
    CHECK(has(r.stdout_text, "3.4.5"));
    CHECK(has(r.stdout_text, "disk"));
    CHECK(has(r.stdout_text, "trust"));
    CHECK(has(r.stdout_text, "last run"));

    std::error_code ec;
    fs::remove_all(work, ec);
}

TEST_CASE("apps --json carries the structured fields") {
    test::TempLexeHome home;
    const fs::path work = test::unique_temp_dir("lexe-apps-");
    fs::create_directories(work);
    const std::string id = install_app(work);

    const util::ProcessResult r = run({"apps", "--json"});
    CHECK(r.exit_code == 0);
    const json j = json::parse(r.stdout_text);
    REQUIRE(j.is_array());
    REQUIRE(j.size() == 1);
    CHECK(j[0].at("id") == id);
    CHECK(j[0].at("version") == "3.4.5");
    CHECK(j[0].at("publisher") == "Acme Publisher");
    CHECK(j[0].at("diskBytes").get<std::uint64_t>() > 0);
    CHECK_FALSE(j[0].at("trust").get<std::string>().empty());

    std::error_code ec;
    fs::remove_all(work, ec);
}

TEST_CASE("apps reports an empty install set clearly") {
    test::TempLexeHome home;
    const util::ProcessResult r = run({"apps"});
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "No applications installed"));
    CHECK(run({"apps", "--json"}).stdout_text.find("[]") != std::string::npos);
}

} // TEST_SUITE("cli_apps")

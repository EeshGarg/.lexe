// `lexe inspect` tests (DX2): build a real signed package with an ELF payload
// through the CLI, then inspect it — human, --json, and --manifest — asserting
// the formatted view, structured output, and exit codes.

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

// Build a signed package with a conforming dynamic ELF payload; return its path.
fs::path build_package(const fs::path& work) {
    fs::create_directories(work / "proj" / "payload" / "bin");
    test::ElfSpec app;
    app.interp = "/lib64/ld-linux-x86-64.so.2";
    app.e_machine = 62; // x86_64
    app.needed = {"libc.so.6"};
    app.version_needs = {"GLIBC_2.17"};
    test::write_elf(work / "proj" / "payload" / "bin" / "app", app);
    util::spit(work / "proj" / "lexe.json", std::string_view(R"({
  "lexeVersion":"0.1","id":"com.example.inspectme","name":"Inspect Me",
  "version":"2.1.0","publisher":{"name":"Demo Publisher","publicKey":"AUTO"},
  "applicationType":"native","architectures":["x86_64"],
  "entrypoint":{"executable":"bin/app","arguments":[]},
  "install":{"scope":"user","mode":"bundled"},"permissions":["network"]
})"));
    REQUIRE(run({"keygen", (work / "k.json").string()}).exit_code == 0);
    const util::ProcessResult b = run({"build", (work / "proj").string(), "-o",
                                       (work / "app.lexe").string(), "--key",
                                       (work / "k.json").string()});
    REQUIRE(b.exit_code == 0);
    return work / "app.lexe";
}

struct Work {
    fs::path dir;
    Work() : dir(test::unique_temp_dir("lexe-inspect-")) {
        fs::create_directories(dir);
    }
    ~Work() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

} // namespace

TEST_SUITE("cli_inspect") {

TEST_CASE("human inspection shows identity, verification, checksum, permissions") {
    Work w;
    const fs::path pkg = build_package(w.dir);
    const util::ProcessResult r = run({"inspect", pkg.string()});
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "Inspect Me"));
    CHECK(has(r.stdout_text, "com.example.inspectme"));
    CHECK(has(r.stdout_text, "Verification:"));
    CHECK(has(r.stdout_text, "PASSED"));
    CHECK(has(r.stdout_text, "Checksum:"));
    CHECK(has(r.stdout_text, "sha256:"));
    CHECK(has(r.stdout_text, "Network access")); // permission explained
    CHECK(has(r.stdout_text, "Compatibility:"));  // the shared report
    CHECK_FALSE(has(r.stdout_text, "\033[")); // plain when captured
}

TEST_CASE("--json is a structured superset") {
    Work w;
    const fs::path pkg = build_package(w.dir);
    const util::ProcessResult r = run({"inspect", pkg.string(), "--json"});
    CHECK(r.exit_code == 0);
    const json j = json::parse(r.stdout_text);
    CHECK(j.at("application").at("id") == "com.example.inspectme");
    CHECK(j.at("verification").at("ok") == true);
    CHECK(j.at("package").at("sha256").get<std::string>().size() == 64);
    CHECK(j.at("publisher").at("identityVerified") == false);
    // The conforming ELF payload verifies against Tux32 Core 1.
    CHECK(j.at("report").at("tux32").at("verdict") == "conformant");
}

TEST_CASE("--manifest dumps the raw manifest JSON") {
    Work w;
    const fs::path pkg = build_package(w.dir);
    const util::ProcessResult r = run({"inspect", pkg.string(), "--manifest"});
    CHECK(r.exit_code == 0);
    const json j = json::parse(r.stdout_text);
    CHECK(j.at("lexeVersion") == "0.1");
    CHECK(j.at("id") == "com.example.inspectme");
}

TEST_CASE("a missing package is a not-found error") {
    Work w;
    CHECK(run({"inspect", (w.dir / "nope.lexe").string()}).exit_code == 4);
}

} // TEST_SUITE("cli_inspect")

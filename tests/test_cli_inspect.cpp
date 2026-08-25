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
// `key`/`out`/`version` vary so a second package can carry the SAME App ID under
// a DIFFERENT signing key (the local-trust conflict case below).
fs::path build_package(const fs::path& work, const std::string& key = "k.json",
                       const std::string& out = "app.lexe",
                       const std::string& version = "2.1.0") {
    fs::create_directories(work / "proj" / "payload" / "bin");
    test::ElfSpec app;
    app.interp = "/lib64/ld-linux-x86-64.so.2";
    app.e_machine = 62; // x86_64
    app.needed = {"libc.so.6"};
    app.version_needs = {"GLIBC_2.17"};
    test::write_elf(work / "proj" / "payload" / "bin" / "app", app);
    util::spit(work / "proj" / "lexe.json", std::string_view(R"({
  "lexeVersion":"0.1","id":"com.example.inspectme","name":"Inspect Me",
  "version":")" + version + R"(","publisher":{"name":"Demo Publisher","publicKey":"AUTO"},
  "applicationType":"native","architectures":["x86_64"],
  "entrypoint":{"executable":"bin/app","arguments":[]},
  "install":{"scope":"user","mode":"bundled"},"permissions":["network"]
})"));
    REQUIRE(run({"keygen", (work / key).string()}).exit_code == 0);
    const util::ProcessResult b = run({"build", (work / "proj").string(), "-o",
                                       (work / out).string(), "--key",
                                       (work / key).string()});
    REQUIRE(b.exit_code == 0);
    return work / out;
}

struct Work {
    // `lexe inspect` reads the LOCAL trust store to say whether `lexe install`
    // would refuse the package it just passed, so it is no longer a
    // home-directory-free command: without this the child would read the
    // developer's real ~/.lexe, which no test in this suite may do.
    test::TempLexeHome home;
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
    // Nothing is installed under this App ID, so there is no local conflict to
    // report and the local-trust block stays off the screen entirely.
    CHECK_FALSE(has(r.stdout_text, "Local trust on this machine"));
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
    // Local trust is stated even when there is no conflict, so a script reads a
    // field rather than having to treat an absent one as consent. It is a
    // SIBLING of "verification", never a stage inside it.
    CHECK(j.at("localTrust").at("installWouldRefuse") == false);
    CHECK(j.at("localTrust").at("keyState") == "first-seen");
    CHECK(j.at("localTrust").at("appId") == "com.example.inspectme");
}

TEST_CASE("inspect keeps its PASSED verdict but flags a package `install` "
          "would refuse over a changed key") {
    Work w;
    // Same App ID, two different publisher keys. Install the first; the second
    // is then a package that passes §6 in full and that `lexe install` refuses
    // outright (exit 7) — the case where "PASSED" alone misled the reader.
    const fs::path first = build_package(w.dir, "k1.json", "one.lexe", "1.0.0");
    REQUIRE(run({"install", first.string(), "--yes"}).exit_code == 0);
    const fs::path second = build_package(w.dir, "k2.json", "two.lexe", "2.0.0");

    const util::ProcessResult r = run({"inspect", second.string()});
    // The §6 verdict and the exit code are about the PACKAGE and are unchanged.
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "Verification:"));
    CHECK(has(r.stdout_text, "PASSED"));
    // …and the local consequence is stated separately, in the shared wording.
    CHECK(has(r.stdout_text, "Local trust on this machine"));
    CHECK(has(r.stdout_text, "NOT part of the verification result above"));
    CHECK(has(r.stdout_text, "`lexe install` will refuse this package (exit 7)"));
    CHECK(has(r.stdout_text, "Expected (already installed):"));
    CHECK(has(r.stdout_text, "Presented (this package):"));
    // The remedy the refusal itself names — not a second, divergent wording.
    CHECK(has(r.stdout_text, "lexe remove com.example.inspectme --purge-data"));
    CHECK(has(r.stdout_text, "lexe trust forget com.example.inspectme"));

    const json j = json::parse(
        run({"inspect", second.string(), "--json"}).stdout_text);
    CHECK(j.at("verification").at("ok") == true); // still a passing package
    CHECK(j.at("localTrust").at("installWouldRefuse") == true);
    CHECK(j.at("localTrust").at("keyState") == "changed");
    CHECK(j.at("localTrust").at("expectedFingerprint").is_string());

    // The promise the note makes is the behaviour install actually has.
    CHECK(run({"install", second.string(), "--yes"}).exit_code == 7);
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

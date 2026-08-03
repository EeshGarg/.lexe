// End-to-end tests for `lexe sdk verify` (portability milestone): the built
// CLI is driven against crafted ELF fixtures and its typed verdict, JSON shape,
// and exit codes are checked. Exercises the SAME dependency+verify path the
// library tests cover, but through the real process boundary a build/CI uses.

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

// The built `lexe` CLI: LEXE_TEST_BINARY / LEXE_CLI (set by CTest), then the
// path baked in at compile time (mirrors tests/test_cli_e2e.cpp).
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

util::ProcessResult sdk(const std::vector<std::string>& args) {
    std::vector<std::string> argv{cli_binary().string(), "sdk", "verify"};
    argv.insert(argv.end(), args.begin(), args.end());
    return util::run_process(argv);
}

struct Scratch {
    fs::path dir;
    Scratch() : dir(test::unique_temp_dir("lexe-cli-sdk-")) {
        fs::create_directories(dir);
    }
    ~Scratch() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

test::ElfSpec dyn_app() {
    test::ElfSpec s;
    s.interp = "/lib64/ld-linux-x86-64.so.2";
    s.e_machine = 62; // x86_64
    return s;
}

} // namespace

TEST_SUITE("cli_sdk_verify") {

TEST_CASE("a conformant binary verifies with exit 0 and a typed JSON verdict") {
    Scratch s;
    test::ElfSpec app = dyn_app();
    app.needed = {"libc.so.6"};
    app.version_needs = {"GLIBC_2.17"};
    const fs::path bin = s.dir / "app";
    test::write_elf(bin, app);

    const util::ProcessResult r = sdk({bin.string(), "--json"});
    CHECK(r.exit_code == 0);
    const json j = json::parse(r.stdout_text);
    CHECK(j.at("tool") == "lexe sdk verify");
    CHECK(j.at("verdict") == "conformant");
    CHECK(j.at("conformant") == true);
    CHECK(j.at("profile").at("id") == "tux32-core-1");
    CHECK(j.at("profile").at("glibcCeiling") == "2.31");
    CHECK(j.at("architecture") == "x86_64");
    CHECK(j.at("requiredGlibc") == "2.17");
    // libc is host-provided, never a bundle candidate.
    bool libc_is_host = false;
    for (const auto& h : j.at("hostInterfaces")) {
        if (h == "libc.so.6") libc_is_host = true;
    }
    CHECK(libc_is_host);
}

TEST_CASE("an above-ceiling binary is rejected with exit 3 and names the offender") {
    Scratch s;
    test::ElfSpec app = dyn_app();
    app.needed = {"libc.so.6"};
    app.version_needs = {"GLIBC_2.34"}; // the real Ubuntu-24.04-built case
    const fs::path bin = s.dir / "app";
    test::write_elf(bin, app);

    const util::ProcessResult r = sdk({bin.string(), "--json"});
    CHECK(r.exit_code == 3); // non-conformant → verification-failure exit
    const json j = json::parse(r.stdout_text);
    CHECK(j.at("verdict") == "symbol-ceiling-exceeded");
    CHECK(j.at("conformant") == false);
    CHECK(j.at("requiredGlibc") == "2.34");
    REQUIRE(j.at("symbolOffenders").size() >= 1);
    CHECK(j.at("symbolOffenders")[0].at("version") == "GLIBC_2.34");
}

TEST_CASE("the human report carries the verdict and detail") {
    Scratch s;
    test::ElfSpec app = dyn_app();
    app.needed = {"libc.so.6", "libGL.so.1"}; // forbidden host driver
    app.version_needs = {"GLIBC_2.17"};
    const fs::path bin = s.dir / "app";
    test::write_elf(bin, app);

    const util::ProcessResult r = sdk({bin.string()});
    CHECK(r.exit_code == 3);
    CHECK(r.stdout_text.find("VERDICT: forbidden-dependency") !=
          std::string::npos);
    CHECK(r.stdout_text.find("libGL.so.1") != std::string::npos);
}

TEST_CASE("a non-ELF target is invalid input (non-conformant, exit 3)") {
    Scratch s;
    const fs::path txt = s.dir / "notelf";
    util::spit(txt, std::string_view("#!/bin/sh\necho hi\n"));
    const util::ProcessResult r = sdk({txt.string(), "--json"});
    CHECK(r.exit_code == 3);
    CHECK(json::parse(r.stdout_text).at("verdict") == "invalid-input");
}

TEST_CASE("a missing path is a not-found error (exit 4)") {
    Scratch s;
    const util::ProcessResult r = sdk({(s.dir / "does-not-exist").string()});
    CHECK(r.exit_code == 4);
}

TEST_CASE("an unknown profile is a usage error (exit 2)") {
    Scratch s;
    test::ElfSpec app = dyn_app();
    app.version_needs = {"GLIBC_2.17"};
    const fs::path bin = s.dir / "app";
    test::write_elf(bin, app);
    const util::ProcessResult r =
        sdk({bin.string(), "--profile", "tux32-core-99"});
    CHECK(r.exit_code == 2);
}

TEST_CASE("an explicit --profile tux32-core-1 is accepted") {
    Scratch s;
    test::ElfSpec app = dyn_app();
    app.needed = {"libc.so.6"};
    app.version_needs = {"GLIBC_2.17"};
    const fs::path bin = s.dir / "app";
    test::write_elf(bin, app);
    const util::ProcessResult r =
        sdk({bin.string(), "--profile", "tux32-core-1"});
    CHECK(r.exit_code == 0);
}

} // TEST_SUITE("cli_sdk_verify")

// CLI user-experience tests (DX6): grouped help, shell-completion groundwork,
// and usage/exit-code discipline, driven through the built `lexe` binary.

#include <doctest/doctest.h>

#include "core/util.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;

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

} // namespace

TEST_SUITE("cli_ux") {

TEST_CASE("help is grouped into clear sections with examples") {
    const util::ProcessResult r = run({"help"});
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "Applications"));
    CHECK(has(r.stdout_text, "Developer"));
    CHECK(has(r.stdout_text, "Trust & verification"));
    CHECK(has(r.stdout_text, "System"));
    CHECK(has(r.stdout_text, "Examples"));
    // The output is plain (no ANSI) when captured (not a TTY).
    CHECK_FALSE(has(r.stdout_text, "\033["));
}

TEST_CASE("help lists the full command surface, including the new commands") {
    const std::string h = run({"help"}).stdout_text;
    for (const char* cmd : {"install", "run", "apps", "inspect", "build",
                            "sdk verify", "config", "completion", "version"}) {
        CHECK(has(h, cmd));
    }
}

TEST_CASE("completion emits a sourceable bash script") {
    const util::ProcessResult r = run({"completion", "bash"});
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "complete -F _lexe lexe"));
    CHECK(has(r.stdout_text, "compgen"));
}

TEST_CASE("completion offers subcommands for grouped commands") {
    const std::string s = run({"completion", "bash"}).stdout_text;
    CHECK(has(s, "verify"));                  // sdk verify
    CHECK(has(s, "show block unblock forget")); // trust
    CHECK(has(s, "list get set reset path"));   // config
}

TEST_CASE("completion rejects an unsupported shell as a usage error") {
    CHECK(run({"completion", "zsh"}).exit_code == 2);
}

TEST_CASE("a mistyped command is a usage error (with a suggestion on stderr)") {
    // The suggestion text goes to stderr; here we assert the typed exit code.
    CHECK(run({"instal"}).exit_code == 2);
    CHECK(run({"aps"}).exit_code == 2);
}

TEST_CASE("an unknown command is a usage error (exit 2)") {
    CHECK(run({"frobnicate"}).exit_code == 2);
}

TEST_CASE("a command missing its required argument is a usage error") {
    CHECK(run({"install"}).exit_code == 2);
    CHECK(run({"run"}).exit_code == 2);
}

} // TEST_SUITE("cli_ux")

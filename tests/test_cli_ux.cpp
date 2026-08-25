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

TEST_CASE("completion emits a sourceable zsh script") {
    const util::ProcessResult r = run({"completion", "zsh"});
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "#compdef lexe"));
    CHECK(has(r.stdout_text, "compdef _lexe lexe"));
    CHECK(has(r.stdout_text, "compadd"));
}

TEST_CASE("both shells complete the same command and subcommand words") {
    const std::string bash = run({"completion", "bash"}).stdout_text;
    const std::string zsh = run({"completion", "zsh"}).stdout_text;
    // One shared table drives both, so neither can silently miss a command.
    for (const char* word : {"install", "run", "apps", "inspect", "sdk",
                             "trust", "config", "completion", "version"}) {
        CHECK(has(bash, word));
        CHECK(has(zsh, word));
    }
    CHECK(has(zsh, "show block unblock forget")); // trust subcommands
    CHECK(has(zsh, "list get set reset path"));   // config subcommands
}

TEST_CASE("completion rejects an unsupported shell as a usage error") {
    CHECK(run({"completion", "tcsh"}).exit_code == 2);
    CHECK(run({"completion", "powershell"}).exit_code == 2);
}

// --- per-command help -------------------------------------------------------

TEST_CASE("every command answers --help with its own usage, not the banner") {
    // The full command surface, from the CLI's own list.
    for (const char* cmd :
         {"install", "run", "list", "apps", "info", "inspect", "update",
          "rollback", "repair", "remove", "gc", "build", "analyze", "sdk",
          "pack", "keygen", "sign-update", "verify", "trust", "source",
          "config", "integrate", "completion", "version", "help"}) {
        const util::ProcessResult r = run({cmd, "--help"});
        INFO("command: " << std::string(cmd));
        CHECK(r.exit_code == 0);
        // Its own usage line, and NOT the whole banner.
        CHECK(has(r.stdout_text, "usage: lexe "));
        CHECK(has(r.stdout_text, cmd));
        CHECK_FALSE(has(r.stdout_text, "Linux applications, made simple."));
    }
}

TEST_CASE("-h is accepted wherever --help is") {
    const util::ProcessResult r = run({"install", "-h"});
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "usage: lexe install"));
}

TEST_CASE("`lexe help <command>` answers about that one command") {
    const util::ProcessResult r = run({"help", "inspect"});
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "usage: lexe inspect"));
    CHECK_FALSE(has(r.stdout_text, "Linux applications, made simple."));
}

TEST_CASE("`lexe help <typo>` is a usage error, like any unknown command") {
    CHECK(run({"help", "instal"}).exit_code == 2);
}

TEST_CASE("bare `lexe help` still shows the full grouped help") {
    const util::ProcessResult r = run({"help"});
    CHECK(r.exit_code == 0);
    CHECK(has(r.stdout_text, "Linux applications, made simple."));
}

TEST_CASE("--help after `--` belongs to the application, not to lexe") {
    // `lexe run <id> -- --help` must not print lexe's help; the id is not
    // installed here, so it fails as not-found (exit 4) having passed --help on.
    const util::ProcessResult r = run({"run", "org.example.absent", "--", "--help"});
    CHECK(r.exit_code == 4);
    CHECK_FALSE(has(r.stdout_text, "usage: lexe run"));
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

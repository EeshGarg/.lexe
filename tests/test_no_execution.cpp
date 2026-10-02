// "Package-controlled content is never executed to verify a package."
//
// docs/HARDENING.md lists this among the proven security invariants, in a table
// whose own header defines "proven" as "an automated test fails if the property
// regresses". Its Proven-by column reads: `test_health_check`, design (§D note).
//
// `test_health_check.cpp` holds four cases -- a healthy install, a missing
// entrypoint, an unhealthy upgrade, a corrupted payload -- and **not one of
// them observes whether anything ran.** The only statement that the health
// check executes nothing is a comment at the top of that file. "Design" is not
// an observer and a §D note is not a test.
//
// So the invariant most directly about NOT doing something had nothing watching
// it. Adding a launch probe to the health check tomorrow -- a tempting change,
// because actually running the entrypoint catches unhealthy packages a static
// check cannot -- would leave the whole suite green while turning
// `lexe install` into a command that executes untrusted, publisher-controlled
// code as a side effect of checking it. That is precisely what the invariant
// exists to prevent.
//
// This file is that observer. It is deliberately NOT in test_health_check.cpp:
// the health check is one caller of the rule, and the rule is about the whole
// install path.
//
// docs/ERRORS.md §7 practice 2 -- give a check an observer that is not itself
// -- applies to this observer too. "The sentinel file does not exist" passes
// trivially if the sentinel could never have appeared: a typo in the path, an
// environment variable the payload never reads, a compiler that quietly
// produced something inert. So the first subcase RUNS the same binary and
// requires the sentinel TO appear. Only once execution is known to be
// detectable does its absence mean anything.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/paths.hpp"
#include "lexe/base/util.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/package/package.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/verify/verify.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>

#ifndef _WIN32

namespace fs = std::filesystem;

namespace {

/// The real `lexe` binary: `lexe verify` and `lexe inspect` are the surfaces a
/// person points at an untrusted file, and `inspect` runs analysis the library
/// `verify_package()` does not (dependencies, Tux32, compatibility). Observing
/// only the library call would leave both commands unwatched.
fs::path cli_binary() {
#ifdef LEXE_TEST_BINARY_PATH
    return fs::path(LEXE_TEST_BINARY_PATH);
#else
    return fs::path("lexe");
#endif
}

} // namespace
using namespace lexe;

namespace {

const char* kId = "com.example.exec-probe";
const char* kSentinelVar = "LEXE_TEST_EXEC_SENTINEL";

// Sets an environment variable for its lifetime. The variable must be visible
// to anything the installer might spawn, and the child inherits this process's
// environment -- so it has to be set here, not passed per-call.
class ScopedEnv {
public:
    ScopedEnv(const char* name, const std::string& value) : name_(name) {
        if (const char* old = std::getenv(name)) {
            had_ = true;
            old_ = old;
        }
        ::setenv(name, value.c_str(), 1);
    }
    ~ScopedEnv() {
        if (had_) ::setenv(name_, old_.c_str(), 1);
        else ::unsetenv(name_);
    }
    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
    const char* name_;
    bool had_ = false;
    std::string old_;
};

// Writes a sentinel file named by an environment variable, then exits 0.
//
// The path arrives through the environment rather than being baked into the
// source because helpers.hpp caches compiled programs keyed on the source text;
// a per-run path would defeat that cache and recompile for every case. It also
// keeps the program honest: it does exactly one externally visible thing, and
// that thing is the thing being detected.
const char* kSentinelSource = R"C(
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    const char* p = getenv("LEXE_TEST_EXEC_SENTINEL");
    if (p && *p) {
        FILE* f = fopen(p, "w");
        if (f) { fputs("this program ran\n", f); fclose(f); }
    }
    printf("exec probe\n");
    return 0;
}
)C";

} // namespace

TEST_SUITE("no_execution") {

TEST_CASE("installing a package never executes the package's own entrypoint") {
    if (!test::have_native_compiler()) {
        MESSAGE("no usable C compiler: a payload that reports having run "
                "cannot be built, so execution could not be detected either "
                "way and asserting its absence would prove nothing");
        return;
    }

    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();

    // A normal app tree, with the stock entrypoint replaced by the probe.
    test::TestAppSpec spec;
    spec.id = kId;
    spec.version = "1.0.0";
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree = test::make_test_app_tree(work / "tree", spec);

    const fs::path entry = tree.payload_dir / spec.entrypoint;
    REQUIRE(test::compile_native_executable(entry, kSentinelSource));

    const fs::path sentinel = work / "it-ran";
    const std::string sentinel_str = sentinel.string();

    SUBCASE("the probe can detect execution at all") {
        // Run the very binary that is about to be packaged. If this does not
        // produce the sentinel, every "sentinel is absent" assertion below is
        // vacuous -- satisfied by a payload incapable of reporting that it ran,
        // rather than by a runtime that declined to run it.
        fs::remove(sentinel);
        REQUIRE_FALSE(fs::exists(sentinel));

        ScopedEnv guard(kSentinelVar, sentinel_str);
        const util::ProcessResult r = util::run_process({entry.string()});

        CHECK(r.exit_code == 0);
        CHECK(fs::exists(sentinel)); // the detector detects
    }

    SUBCASE("verify and install do not run it") {
        fs::remove(sentinel);
        REQUIRE_FALSE(fs::exists(sentinel));

        // Set for the whole subcase: anything the installer spawns inherits
        // this environment, so if some stage executes payload content, the
        // sentinel appears.
        ScopedEnv guard(kSentinelVar, sentinel_str);

        PackageWriter::Inputs in;
        in.payload_dir = tree.payload_dir;
        in.manifest_file = tree.manifest_file;
        const fs::path pkg = work / "probe.lexe";
        PackageWriter::write(in, key, pkg);

        // The whole §6 pipeline, including the payload-role stage, which reads
        // the entrypoint's bytes to decide whether they are an ELF. Reading
        // them is the permitted way to answer that question; running them is
        // not.
        const VerificationReport report =
            verify_package(pkg, /*check_architecture=*/true);
        CHECK(report.ok());
        CHECK_FALSE(fs::exists(sentinel));

        // The read-only CLI surfaces, human and --json. Exit 0 is required so
        // a command that failed before reaching the package cannot pass as
        // "did not execute it".
        for (const std::vector<std::string>& args :
             {std::vector<std::string>{"verify", pkg.string()},
              std::vector<std::string>{"verify", pkg.string(), "--json"},
              std::vector<std::string>{"inspect", pkg.string()},
              std::vector<std::string>{"inspect", pkg.string(), "--json"}}) {
            std::vector<std::string> argv{cli_binary().string()};
            argv.insert(argv.end(), args.begin(), args.end());
            INFO("lexe " << args[0] << (args.size() > 2 ? " --json" : ""));
            CHECK(util::run_process(argv).exit_code == 0);
            CHECK_FALSE(fs::exists(sentinel));
        }

        // And the install path, which additionally runs the pre-activation
        // health check -- the stage most tempting to implement by launching
        // the entrypoint to see whether it comes up.
        Installer installer(paths);
        CHECK_NOTHROW(installer.install(pkg));
        CHECK(Registry(paths).is_installed(kId));

        CHECK_FALSE(fs::exists(sentinel));
    }
}

} // TEST_SUITE("no_execution")

#endif // _WIN32

// `lexe inspect` tests (DX2): build a real signed package with an ELF payload
// through the CLI, then inspect it — human, --json, and --manifest — asserting
// the formatted view, structured output, and exit codes.

#include <doctest/doctest.h>

#include "elf_builder.hpp"
#include "helpers.hpp"

#include "lexe/base/util.hpp"
#include "lexe/package/crypto.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <map>
#include <optional>

#ifndef _WIN32
#include <unistd.h>
#endif
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
                       const std::string& version = "2.1.0",
                       const std::string& name_json = "Inspect Me") {
    fs::create_directories(work / "proj" / "payload" / "bin");
    test::ElfSpec app;
    app.interp = test::host_interpreter();
    app.e_machine = test::host_machine();
    app.needed = {"libc.so.6"};
    app.version_needs = {"GLIBC_2.17"};
    test::write_elf(work / "proj" / "payload" / "bin" / "app", app);
    util::spit(work / "proj" / "lexe.json", std::string_view(R"({
  "lexeVersion":"0.1","id":"com.example.inspectme","name":")" + name_json + R"(",
  "version":")" + version + R"(","publisher":{"name":"Demo Publisher","publicKey":"AUTO"},
  "applicationType":"native","architectures":[")" + host_architecture() + R"("],
  "entrypoint":{"executable":"bin/app","arguments":[]},
  "install":{"scope":"user","mode":"bundled"},"permissions":["network"],
  "runtimeProfile":"core-portable"
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
    CHECK(j.at("authenticated") == true);
    // The inventory is the archive's structure. Observed independently: the
    // entry set is fixed by FORMAT §2 for this package, and the payload digest
    // must equal the SHA-256 of the file this test wrote to disk.
    {
        std::map<std::string, json> by_path;
        for (const json& e : j.at("inventory")) by_path[e.at("path")] = e;
        CHECK(by_path.size() == 5);
        for (const char* p : {"lexe.json", "metadata/hashes.json", "payload/bin/app",
                              "signatures/manifest.sig", "signatures/payload.sig"}) {
            CAPTURE(p);
            CHECK(by_path.count(p) == 1);
        }
        CHECK(by_path.at("payload/bin/app").at("sha256") ==
              crypto::sha256_file_hex(w.dir / "proj" / "payload" / "bin" / "app"));
        CHECK(by_path.at("payload/bin/app").at("coveredBy") == "metadata/hashes.json");
        CHECK(by_path.at("lexe.json").at("coveredBy") == "signatures/manifest.sig");
        CHECK(by_path.at("metadata/hashes.json").at("coveredBy") ==
              "signatures/payload.sig");
    }
    CHECK(j.at("application").at("id") == "com.example.inspectme");
    CHECK(j.at("verification").at("ok") == true);
    CHECK(j.at("package").at("sha256").get<std::string>().size() == 64);
    CHECK(j.at("publisher").at("identityVerified") == false);
    // The conforming ELF payload verifies against Tux32 Core 1 -- which is
    // defined for x86_64 only (docs/TUX32.md); the same host-shaped payload on
    // any other host is, by that spec, an unsupported architecture.
    CHECK(j.at("report").at("tux32").at("verdict") ==
          (host_architecture() == "x86_64" ? "conformant"
                                           : "unsupported-architecture"));
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
    CHECK(has(r.stdout_text, "lexe purge com.example.inspectme"));
    CHECK_FALSE(has(r.stdout_text, "--purge-data"));

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

TEST_CASE("a package's own text cannot forge lines on the terminal") {
    // A signed name carrying a newline printed a fake "Verification: PASSED"
    // row under Name; an ESC sequence reached stdout raw. Package text is now
    // escaped (\x0A, \x1B) wherever human output shows it.
    Work w;
    const std::string evil =
        R"(Evil\n  Verification:   PASSED — forged\u001b[2K‮)";
    const fs::path pkg = build_package(w.dir, "k.json", "app.lexe", "2.1.0", evil);
    for (const char* cmd : {"inspect", "verify", "info"}) {
        CAPTURE(cmd);
        const util::ProcessResult r = run({cmd, pkg.string()});
        // No raw ESC and no raw RTL override anywhere in the output.
        CHECK(r.stdout_text.find('\x1b') == std::string::npos);
        CHECK(r.stdout_text.find("\xE2\x80\xAE") == std::string::npos);
        // The forged text never starts a line of its own.
        CHECK_FALSE(has(r.stdout_text, "\n  Verification:   PASSED \xE2\x80\x94 forged"));
        // ...but it is still visible, escaped, so nothing is hidden either.
        CHECK(has(r.stdout_text, "Evil\\x0A"));
    }
}

#ifndef _WIN32
TEST_CASE("verify --json always emits a verdict, even about bytes that are not UTF-8") {
    // nlohmann's dump() throws on invalid UTF-8, so a rejection whose detail
    // (or file name) carried such bytes printed NOTHING on stdout and exited 1
    // -- a machine consumer got no verdict for a fail-closed rejection.
    Work w;
    const fs::path bad = w.dir / std::string("pkg-\xff\xfe.lexe");
    util::spit(bad, std::string_view("not a zip"));
    const util::ProcessResult r = run({"verify", bad.string(), "--json"});
    INFO(r.stderr_text);
    CHECK(r.exit_code == 3);
    REQUIRE_FALSE(r.stdout_text.empty());
    const json doc = json::parse(r.stdout_text); // valid UTF-8 JSON
    CHECK(doc.at("ok") == false);
}
#endif

TEST_CASE("inspect describes only what it examined, and says so") {
    Work w;
    const crypto::KeyPair key = test::make_keypair();

    SUBCASE("a portable package ships no binary, so nothing is analysed") {
        // Before: "Tux32: invalid-input" and "[ ok ]" for every distribution,
        // from a dependency list that was empty because nothing was examined.
        const fs::path pkg = test::make_portable_package(w.dir, key);
        const util::ProcessResult j = run({"inspect", pkg.string(), "--json"});
        REQUIRE(j.exit_code == 0);
        const json doc = json::parse(j.stdout_text);
        CHECK(doc.at("authenticated") == true);
        CHECK(doc.at("analysis").at("performed") == false);
        CHECK_FALSE(doc.contains("report"));
        const util::ProcessResult h = run({"inspect", pkg.string()});
        CHECK(has(h.stdout_text, "not performed"));
        CHECK_FALSE(has(h.stdout_text, "[ ok ]"));
        CHECK_FALSE(has(h.stdout_text, "Tux32"));
    }

    SUBCASE("no declared runtimeProfile is no profile, not Core Portable") {
        // FORMAT §5.7: "MUST NOT substitute a default".
        const fs::path pkg = test::make_test_package(w.dir, key);
        const util::ProcessResult j = run({"inspect", pkg.string(), "--json"});
        REQUIRE(j.exit_code == 0);
        const json doc = json::parse(j.stdout_text);
        REQUIRE(doc.at("analysis").at("performed") == true);
        CHECK(doc.at("report").at("runtimeProfile").is_null());
        CHECK_FALSE(doc.at("report").contains("profileAssessment"));
        CHECK_FALSE(doc.at("report").contains("tux32"));
        CHECK(has(run({"inspect", pkg.string()}).stdout_text,
                  "none declared (not assessed)"));
    }

    SUBCASE("a package that fails verification is marked BEFORE its claims") {
        const fs::path pkg = test::make_test_package(w.dir, key);
        test::tamper_entry(pkg, "signatures/manifest.sig",
                           [](std::vector<std::uint8_t>& b) {
                               std::fill(b.begin(), b.end(), std::uint8_t{0});
                           });
        const util::ProcessResult h = run({"inspect", pkg.string()});
        CHECK(h.exit_code == 3);
        const std::size_t banner = h.stdout_text.find("NOT AUTHENTIC");
        const std::size_t claim = h.stdout_text.find("Publisher:");
        REQUIRE(banner != std::string::npos);
        REQUIRE(claim != std::string::npos);
        CHECK(banner < claim);
        const json doc = json::parse(run({"inspect", pkg.string(), "--json"}).stdout_text);
        CHECK(doc.at("authenticated") == false);
        CHECK(doc.at("analysis").at("performed") == false);
        CHECK_FALSE(doc.contains("report"));
    }
}

#ifndef _WIN32
TEST_CASE("inspect's scratch space cannot be redirected by a pre-planted link") {
    // inspect extracts the payload to analyse it. It used a PREDICTABLE name in
    // the shared temp directory -- "lexe-inspect-" + the first 16 hex digits of
    // the package's SHA-256 -- and ignored the errors from clearing and
    // creating it. Whoever made the package knows its hash, so another local
    // user could plant that name as a link to a directory the victim can write
    // (~/.config/autostart, say). In a sticky /tmp the victim cannot delete the
    // link, creating "it" succeeds because it exists, the extraction root is
    // resolved THROUGH the link, and every payload file lands in the victim's
    // directory -- all of it "under the root", so the per-entry escape check
    // has nothing to object to.
    Work w;
    const fs::path pkg = build_package(w.dir);
    const fs::path tmp = w.dir / "shared-tmp";
    const fs::path victim = w.dir / "victim-dir";
    fs::create_directories(tmp);
    fs::create_directories(victim);
    const std::string sha = crypto::sha256_file_hex(pkg);
    const fs::path planted = tmp / ("lexe-inspect-" + sha.substr(0, 16));
    fs::create_directory_symlink(victim, planted);

    const auto inspect_with_tmpdir = [&] {
        const std::optional<std::string> old = util::get_env("TMPDIR");
        util::set_env("TMPDIR", tmp.string());
        const util::ProcessResult r = run({"inspect", pkg.string()});
        if (old) util::set_env("TMPDIR", *old); else util::unset_env("TMPDIR");
        return r;
    };

    // The observer throughout: the victim directory's contents, listed
    // directly -- independent of anything inspect reports about itself. The
    // package has a payload file (bin/app) that WOULD land there.
    REQUIRE(fs::is_empty(victim));

    SUBCASE("an ordinary writable temp directory: analysis runs, privately") {
        const util::ProcessResult r = inspect_with_tmpdir();
        INFO(r.stdout_text << r.stderr_text);
        CHECK(r.exit_code == 0);
        // The fix is not "stop analysing".
        CHECK(has(r.stdout_text, "Dependencies:"));
        CHECK(fs::is_empty(victim));
        // And someone else's entry is not inspect's to delete.
        CHECK(fs::is_symlink(fs::symlink_status(planted)));
    }

    SUBCASE("the planted link cannot be removed (the sticky-/tmp case)") {
        // In a real sticky /tmp the victim cannot delete ANOTHER user's entry;
        // one user cannot plant a link owned by someone else, so the same
        // inability is made by taking write permission off the directory. The
        // first version of this test omitted it -- inspect deleted its own
        // user's link and the test passed against the vulnerable code. With it,
        // the vulnerable code wrote bin/app into the victim directory.
        if (::geteuid() == 0) {
            MESSAGE("BLOCKED: running as root, which ignores directory "
                    "permissions, so a non-deletable planted link cannot be "
                    "arranged");
            return;
        }
        fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_exec);
        struct Restore {
            fs::path p;
            ~Restore() {
                std::error_code ec;
                fs::permissions(p, fs::perms::owner_all, ec);
            }
        } restore{tmp};
        const util::ProcessResult r = inspect_with_tmpdir();
        INFO(r.stdout_text << r.stderr_text);
        // Nothing new can be created here either, so inspect may fail; what it
        // must never do is extract through the link.
        CHECK(fs::is_empty(victim));
        CHECK_FALSE(fs::exists(victim / "bin" / "app"));
    }
}
#endif

} // TEST_SUITE("cli_inspect")

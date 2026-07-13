// cli module tests (ARCHITECTURE.md #CLI): drive the built `lexe` binary as
// a subprocess through the complete command surface — keygen, pack, verify,
// info, install (with and without --yes), list, run, update (--check /
// --all), source set, rollback, repair, remove, integrate — asserting exit
// codes (0 ok / 1 runtime error / 2 usage / 3 verification failure / 4 not
// found), stdout contents and registry state. Every test case constructs
// lexe::test::TempLexeHome first, so LEXE_HOME always points into a fresh
// temp directory and the real user profile is never touched; child processes
// inherit that environment.
//
// The binary is located via the LEXE_CLI environment variable (set by
// CTest), falling back to `lexe`/`lexe.exe` next to this test executable.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include <atomic>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;
using nlohmann::json;

namespace {

constexpr const char* kId = "com.example.hello";

/// RAII scratch directory for packages/trees/scripts, OUTSIDE LEXE_HOME.
struct TempWorkDir {
    fs::path dir;
    TempWorkDir() : dir(test::unique_temp_dir("lexe-cli-work-")) {
        fs::create_directories(dir);
    }
    ~TempWorkDir() {
        std::error_code ec;
        fs::remove_all(dir, ec); // best effort
    }
    TempWorkDir(const TempWorkDir&) = delete;
    TempWorkDir& operator=(const TempWorkDir&) = delete;
};

/// Directory containing this test executable (fallback CLI location).
fs::path test_binary_dir() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) return fs::path(buf).parent_path();
    return fs::current_path();
#else
    std::error_code ec;
    const fs::path self = fs::read_symlink("/proc/self/exe", ec);
    if (!ec) return self.parent_path();
    return fs::current_path();
#endif
}

/// The built `lexe` binary under test.
fs::path cli_binary() {
    if (const auto env = util::get_env("LEXE_CLI");
        env.has_value() && !env->empty()) {
        return fs::path(*env);
    }
#ifdef _WIN32
    return test_binary_dir() / "lexe.exe";
#else
    return test_binary_dir() / "lexe";
#endif
}

/// Run `lexe <args…>`, capturing stdout. The child inherits LEXE_HOME.
util::ProcessResult run_cli(const std::vector<std::string>& args) {
    std::vector<std::string> argv;
    argv.reserve(args.size() + 1);
    argv.push_back(cli_binary().string());
    argv.insert(argv.end(), args.begin(), args.end());
    return util::run_process(argv);
}

/// Run `lexe <args…>` with `input` supplied on the child's stdin (through a
/// tiny wrapper script with a `<` redirect — run_process itself has no stdin
/// plumbing). Used for the interactive confirmation prompts.
util::ProcessResult run_cli_stdin(const std::vector<std::string>& args,
                                  const std::string& input,
                                  const fs::path& scratch) {
    static std::atomic<int> counter{0};
    const int n = counter.fetch_add(1);
    const fs::path answer = scratch / ("stdin-" + std::to_string(n) + ".txt");
    util::spit(answer, std::string_view(input));
#ifdef _WIN32
    const fs::path script = scratch / ("stdin-" + std::to_string(n) + ".cmd");
    std::string text = "@echo off\r\n\"" + cli_binary().string() + "\"";
    for (const std::string& arg : args) text += " \"" + arg + "\"";
    text += " < \"" + answer.string() + "\"\r\nexit /b %errorlevel%\r\n";
    util::spit(script, std::string_view(text));
    return util::run_process({"cmd", "/c", script.string()});
#else
    const fs::path script = scratch / ("stdin-" + std::to_string(n) + ".sh");
    std::string text = "#!/bin/sh\nexec \"" + cli_binary().string() + "\"";
    for (const std::string& arg : args) text += " \"" + arg + "\"";
    text += " < \"" + answer.string() + "\"\n";
    util::spit(script, std::string_view(text));
    std::error_code ec;
    fs::permissions(script, fs::perms::owner_all, fs::perm_options::add, ec);
    return util::run_process({"/bin/sh", script.string()});
#endif
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

/// Signed package for `kId` at `version`, optionally with an updates block.
fs::path make_versioned_package(const fs::path& work,
                                const crypto::KeyPair& key,
                                const std::string& version,
                                const std::string& update_url = "") {
    test::TestAppSpec spec;
    spec.id = kId;
    spec.version = version;
    spec.update_url = update_url;
    return test::make_test_package(work, key, spec);
}

/// Signed package whose entrypoint exits with its first argument
/// (default 0) — exercises `lexe run` argument forwarding and exit-code
/// propagation.
fs::path make_exit_code_package(const fs::path& work,
                                const crypto::KeyPair& key,
                                const std::string& id,
                                const std::string& version) {
    test::TestAppSpec spec;
    spec.id = id;
    spec.version = version;
#ifdef _WIN32
    spec.entrypoint = "bin/code.cmd";
#else
    spec.entrypoint = "bin/code.sh";
#endif
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree = test::make_test_app_tree(
        work / ("tree-" + id + "-" + version), spec);
    util::spit(tree.payload_dir / "bin" / "code.cmd",
               std::string_view("@exit /b %1\r\n"));
    util::spit(tree.payload_dir / "bin" / "code.sh",
               std::string_view("#!/bin/sh\nexit \"${1:-0}\"\n"));
#ifndef _WIN32
    std::error_code ec;
    fs::permissions(tree.payload_dir / "bin" / "code.sh",
                    fs::perms::owner_all, fs::perm_options::add, ec);
#endif
    PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path out = work / (id + "-" + version + ".lexe");
    PackageWriter::write(inputs, key, out);
    return out;
}

/// Write update.json + detached .sig (FORMAT-0.1 §7) advertising `package`
/// at `version` on the stable channel. Returns the update.json path.
fs::path write_update_manifest(const fs::path& work,
                               const crypto::KeyPair& key,
                               const std::string& id,
                               const std::string& version,
                               const fs::path& package,
                               const std::string& name = "update.json") {
    const json update = {
        {"lexeVersion", "0.1"},
        {"id", id},
        {"channels",
         {{"stable",
           {{"version", version},
            {"package",
             {{"url", package.string()},
              {"sha256", crypto::sha256_file_hex(package)}}},
            {"minimumRuntime", "0.1"}}}}},
    };
    const std::string text = update.dump(2);
    const fs::path file = work / name;
    util::spit(file, std::string_view(text));
    const std::vector<std::uint8_t> bytes(text.begin(), text.end());
    const crypto::Signature sig = crypto::sign(bytes, key);
    util::spit(fs::path(file.string() + ".sig"), sig.data(), sig.size());
    return file;
}

} // namespace

TEST_SUITE("cli") {

// ------------------------------------------------------- dispatch / usage

TEST_CASE("no arguments -> usage on stderr, exit 2") {
    test::TempLexeHome home;
    const auto r = run_cli({});
    CHECK(r.exit_code == 2);
    CHECK(r.stdout_text.empty()); // usage goes to stderr on error
}

TEST_CASE("help prints the full command surface and exits 0") {
    test::TempLexeHome home;
    const auto r = run_cli({"help"});
    CHECK(r.exit_code == 0);
    for (const char* command :
         {"install", "run", "update", "remove", "repair", "info", "verify",
          "source set", "rollback", "list", "keygen", "pack", "integrate"}) {
        CAPTURE(command);
        CHECK(contains(r.stdout_text, command));
    }
}

TEST_CASE("unknown command and unknown options -> exit 2") {
    test::TempLexeHome home;
    CHECK(run_cli({"frobnicate"}).exit_code == 2);
    CHECK(run_cli({"list", "--frobnicate"}).exit_code == 2);
    CHECK(run_cli({"install"}).exit_code == 2);   // missing operand
    CHECK(run_cli({"verify"}).exit_code == 2);    // missing operand
    CHECK(run_cli({"run"}).exit_code == 2);       // missing id
    CHECK(run_cli({"rollback"}).exit_code == 2);  // missing id
    CHECK(run_cli({"keygen"}).exit_code == 2);    // missing operand
    CHECK(run_cli({"list", "extra"}).exit_code == 2); // unexpected positional
}

// ------------------------------------------------------------------ keygen

TEST_CASE("keygen writes a key file and never prints the private seed") {
    test::TempLexeHome home;
    TempWorkDir work;
    const fs::path keyfile = work.dir / "key.json";

    const auto r = run_cli({"keygen", keyfile.string()});
    CHECK(r.exit_code == 0);
    REQUIRE(fs::is_regular_file(keyfile));

    const json j = json::parse(util::slurp_text(keyfile));
    CHECK(j.at("algorithm").get<std::string>() == "ed25519");
    const std::string public_key = j.at("publicKey").get<std::string>();
    const std::string seed = j.at("privateSeed").get<std::string>();
    CHECK(public_key.rfind("ed25519:", 0) == 0);
    CHECK_FALSE(seed.empty());

    // The public key is announced; the seed is never logged (invariant #5).
    CHECK(contains(r.stdout_text, public_key));
    CHECK_FALSE(contains(r.stdout_text, seed));

    // Refuses to overwrite an existing key file.
    CHECK(run_cli({"keygen", keyfile.string()}).exit_code == 1);
}

// -------------------------------------------------------------------- pack

TEST_CASE("keygen -> pack -> verify round trip, deterministic output") {
    test::TempLexeHome home;
    TempWorkDir work;
    const fs::path keyfile = work.dir / "key.json";
    REQUIRE(run_cli({"keygen", keyfile.string()}).exit_code == 0);
    const std::string public_key =
        json::parse(util::slurp_text(keyfile)).at("publicKey");

    test::TestAppSpec spec;
    spec.public_key = public_key;
    const test::TestAppTree tree =
        test::make_test_app_tree(work.dir / "tree", spec);

    const fs::path out = work.dir / "app.lexe";
    const auto packed = run_cli({"pack", tree.payload_dir.string(),
                                 "--manifest", tree.manifest_file.string(),
                                 "--key", keyfile.string(), "-o",
                                 out.string()});
    CHECK(packed.exit_code == 0);
    CHECK(contains(packed.stdout_text, "Packed"));
    REQUIRE(fs::is_regular_file(out));

    const auto verified = run_cli({"verify", out.string()});
    CHECK(verified.exit_code == 0);
    CHECK(contains(verified.stdout_text, "verification: OK"));

    // FORMAT-0.1 §1: packing the same tree twice is byte-identical.
    const fs::path out2 = work.dir / "app-2.lexe";
    REQUIRE(run_cli({"pack", tree.payload_dir.string(), "--manifest",
                     tree.manifest_file.string(), "--key", keyfile.string(),
                     "-o", out2.string()})
                .exit_code == 0);
    CHECK(util::slurp(out) == util::slurp(out2));
}

TEST_CASE("pack rejects bad invocations and mismatched signing keys") {
    test::TempLexeHome home;
    TempWorkDir work;
    const fs::path keyfile = work.dir / "key.json";
    REQUIRE(run_cli({"keygen", keyfile.string()}).exit_code == 0);
    const std::string public_key =
        json::parse(util::slurp_text(keyfile)).at("publicKey");

    test::TestAppSpec spec;
    spec.public_key = public_key;
    const test::TestAppTree tree =
        test::make_test_app_tree(work.dir / "tree", spec);
    const fs::path out = work.dir / "app.lexe";

    // Missing required options -> usage (2).
    CHECK(run_cli({"pack", tree.payload_dir.string(), "--manifest",
                   tree.manifest_file.string(), "-o", out.string()})
              .exit_code == 2);
    CHECK(run_cli({"pack", tree.payload_dir.string(), "--key",
                   keyfile.string(), "-o", out.string()})
              .exit_code == 2);

    // A signing key that is not the manifest's publisher key would produce a
    // package that can never verify -> refused (1).
    const fs::path other_key = work.dir / "other-key.json";
    REQUIRE(run_cli({"keygen", other_key.string()}).exit_code == 0);
    CHECK(run_cli({"pack", tree.payload_dir.string(), "--manifest",
                   tree.manifest_file.string(), "--key", other_key.string(),
                   "-o", out.string()})
              .exit_code == 1);
    CHECK_FALSE(fs::exists(out));

    // Nonexistent payload directory -> runtime error (1).
    CHECK(run_cli({"pack", (work.dir / "no-such-dir").string(), "--manifest",
                   tree.manifest_file.string(), "--key", keyfile.string(),
                   "-o", out.string()})
              .exit_code == 1);
}

// ------------------------------------------------------------------ verify

TEST_CASE("verify --json reports every stage; tampering exits 3") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    const auto ok = run_cli({"verify", pkg.string(), "--json"});
    CHECK(ok.exit_code == 0);
    const json report = json::parse(ok.stdout_text);
    CHECK(report.at("ok").get<bool>());
    REQUIRE(report.at("stages").size() == 6); // no architecture stage
    CHECK(report["stages"][0]["name"] == "structure");
    CHECK(report["stages"][5]["name"] == "hashes");
    for (const auto& stage : report["stages"]) {
        CHECK(stage.at("ok").get<bool>());
    }

    // Flip one payload byte: the hashes stage must fail, exit code 3.
    test::tamper_entry(pkg, "payload/data.txt",
                       [](std::vector<std::uint8_t>& bytes) {
                           bytes.at(0) ^= 0xFF;
                       });
    const auto bad = run_cli({"verify", pkg.string(), "--json"});
    CHECK(bad.exit_code == 3);
    const json bad_report = json::parse(bad.stdout_text);
    CHECK_FALSE(bad_report.at("ok").get<bool>());
    const auto& last = bad_report["stages"].back();
    CHECK(last.at("name") == "hashes");
    CHECK_FALSE(last.at("ok").get<bool>());

    // Human mode carries the same verdict.
    const auto human = run_cli({"verify", pkg.string()});
    CHECK(human.exit_code == 3);
    CHECK(contains(human.stdout_text, "verification: FAILED (hashes)"));

    // A file that is not a package at all -> structure failure, exit 3.
    CHECK(run_cli({"verify", (work.dir / "missing.lexe").string()})
              .exit_code == 3);
}

// -------------------------------------------------------------------- info

TEST_CASE("info on a package file, human and --json") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    const auto human = run_cli({"info", pkg.string()});
    CHECK(human.exit_code == 0);
    CHECK(contains(human.stdout_text, "Hello App"));
    CHECK(contains(human.stdout_text, kId));
    CHECK(contains(human.stdout_text, "1.0.0"));
    CHECK(contains(human.stdout_text, "bundled"));
    CHECK(contains(human.stdout_text, "Test Publisher"));

    const auto machine = run_cli({"info", pkg.string(), "--json"});
    CHECK(machine.exit_code == 0);
    const json j = json::parse(machine.stdout_text);
    CHECK(j.at("source") == "package");
    CHECK(j.at("manifest").at("id") == kId);
    CHECK(j.at("manifest").at("version") == "1.0.0");
    CHECK(j.at("package").at("payloadSize").get<std::uint64_t>() > 0);
}

TEST_CASE("info on something neither a file nor installed -> exit 4") {
    test::TempLexeHome home;
    const auto r = run_cli({"info", "com.example.absent"});
    CHECK(r.exit_code == 4);
}

// ----------------------------------------------------------------- install

TEST_CASE("install --yes installs; registry, list and info reflect it") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    const auto r = run_cli({"install", pkg.string(), "--yes"});
    CHECK(r.exit_code == 0);
    CHECK(contains(r.stdout_text, "Installed"));
    CHECK(contains(r.stdout_text, kId));

    const Paths paths = Paths::detect();
    const Registry registry(paths);
    REQUIRE(registry.is_installed(kId));
    CHECK(registry.current_version(kId) == "1.0.0");
    CHECK(fs::is_regular_file(registry.version_dir(kId, "1.0.0") /
                              "data.txt"));
    const InstallationRecord record = registry.read_record(kId);
    CHECK(record.channel == "stable");
    CHECK(record.source == pkg.string());

    // list: aligned human table and machine-readable --json.
    const auto listed = run_cli({"list"});
    CHECK(listed.exit_code == 0);
    CHECK(contains(listed.stdout_text, "ID"));
    CHECK(contains(listed.stdout_text, kId));
    CHECK(contains(listed.stdout_text, "1.0.0"));
    CHECK(contains(listed.stdout_text, "Hello App"));

    const auto listed_json = run_cli({"list", "--json"});
    CHECK(listed_json.exit_code == 0);
    const json apps = json::parse(listed_json.stdout_text);
    REQUIRE(apps.is_array());
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].at("id") == kId);
    CHECK(apps[0].at("version") == "1.0.0");

    // info by id resolves the installed application.
    const auto info = run_cli({"info", kId, "--json"});
    CHECK(info.exit_code == 0);
    const json j = json::parse(info.stdout_text);
    CHECK(j.at("source") == "installed");
    CHECK(j.at("installed").at("version") == "1.0.0");

    // Same version again is a runtime error (repair is the reinstall path).
    CHECK(run_cli({"install", pkg.string(), "--yes"}).exit_code == 1);
}

TEST_CASE("install without --yes shows the SPEC primary screen and honors "
          "the stdin answer") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path update_json = work.dir / "update.json"; // policy line only
    const fs::path pkg =
        make_versioned_package(work.dir, key, "1.0.0", update_json.string());

    // Answer "y": the primary screen is printed and the install proceeds.
    const auto yes = run_cli_stdin({"install", pkg.string()}, "y\n", work.dir);
    CHECK(yes.exit_code == 0);
    // SPEC #User Interface: name, publisher, version, type/arch, source,
    // permissions, size, update policy, verification result.
    CHECK(contains(yes.stdout_text, "Hello App"));
    CHECK(contains(yes.stdout_text, "Published by Test Publisher"));
    CHECK(contains(yes.stdout_text, "Version 1.0.0"));
    CHECK(contains(yes.stdout_text, "Source:"));
    CHECK(contains(yes.stdout_text, pkg.string()));
    CHECK(contains(yes.stdout_text, "Application Type:"));
    CHECK(contains(yes.stdout_text, "x86_64"));
    CHECK(contains(yes.stdout_text, "Permissions:"));
    CHECK(contains(yes.stdout_text, "Installation:"));
    CHECK(contains(yes.stdout_text, "Updates:"));
    CHECK(contains(yes.stdout_text, update_json.string()));
    CHECK(contains(yes.stdout_text, "Verification:"));
    CHECK(contains(yes.stdout_text, "[y/N]"));
    CHECK(Registry(Paths::detect()).is_installed(kId));

    REQUIRE(run_cli({"remove", kId, "--yes"}).exit_code == 0);

    // Answer "n": cancelled, nothing installed, exit 1.
    const auto no = run_cli_stdin({"install", pkg.string()}, "n\n", work.dir);
    CHECK(no.exit_code == 1);
    CHECK_FALSE(Registry(Paths::detect()).is_installed(kId));

    // EOF on stdin (no answer at all) also cancels.
    const auto eof = run_cli_stdin({"install", pkg.string()}, "", work.dir);
    CHECK(eof.exit_code == 1);
    CHECK_FALSE(Registry(Paths::detect()).is_installed(kId));
}

TEST_CASE("install refuses a tampered package with exit 3") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    test::tamper_entry(pkg, "payload/data.txt",
                       [](std::vector<std::uint8_t>& bytes) {
                           bytes.at(0) ^= 0xFF;
                       });
    CHECK(run_cli({"install", pkg.string(), "--yes"}).exit_code == 3);
    CHECK_FALSE(Registry(Paths::detect()).is_installed(kId));

    // Nonexistent package file is a structure failure -> exit 3 as well.
    CHECK(run_cli({"install", (work.dir / "nope.lexe").string(), "--yes"})
              .exit_code == 3);
}

TEST_CASE("install --channel records the channel in installation.json") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    REQUIRE(run_cli({"install", pkg.string(), "--yes", "--channel", "beta"})
                .exit_code == 0);
    CHECK(Registry(Paths::detect()).read_record(kId).channel == "beta");
}

// --------------------------------------------------------------------- run

TEST_CASE("run launches the entrypoint, forwards args after -- and "
          "propagates the exit code") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const std::string id = "com.example.exitcode";
    const fs::path pkg = make_exit_code_package(work.dir, key, id, "1.0.0");
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);

    CHECK(run_cli({"run", id}).exit_code == 0);
    CHECK(run_cli({"run", id, "--", "7"}).exit_code == 7);
    CHECK(run_cli({"run", id, "--", "42"}).exit_code == 42);

    // lastRun {at, exitCode} recorded in installation.json (FORMAT-0.1 §9).
    const InstallationRecord record =
        Registry(Paths::detect()).read_record(id);
    CHECK(record.last_exit_code == 42);
    CHECK_FALSE(record.last_run_at.empty());

    CHECK(run_cli({"run", "com.example.absent"}).exit_code == 4);
}

// ------------------------------------------------------------------ update

TEST_CASE("update flow: --check, apply, up to date, --all, rollback") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path update_json = work.dir / "update.json";
    const fs::path pkg1 =
        make_versioned_package(work.dir, key, "1.0.0", update_json.string());
    const fs::path pkg2 =
        make_versioned_package(work.dir, key, "1.1.0", update_json.string());
    write_update_manifest(work.dir, key, kId, "1.1.0", pkg2);

    REQUIRE(run_cli({"install", pkg1.string(), "--yes"}).exit_code == 0);
    const Registry registry(Paths::detect());
    CHECK(registry.read_record(kId).update_url == update_json.string());

    // --check is a dry run: reports availability, changes nothing.
    const auto check = run_cli({"update", kId, "--check"});
    CHECK(check.exit_code == 0);
    CHECK(contains(check.stdout_text, "update available"));
    CHECK(contains(check.stdout_text, "1.1.0"));
    CHECK(registry.current_version(kId) == "1.0.0");

    // Apply: 1.0.0 -> 1.1.0; the previous version is retained.
    const auto applied = run_cli({"update", kId});
    CHECK(applied.exit_code == 0);
    CHECK(contains(applied.stdout_text, "updated"));
    CHECK(registry.current_version(kId) == "1.1.0");
    CHECK(fs::is_directory(registry.version_dir(kId, "1.0.0")));

    // Nothing newer: clean no-op with exit 0.
    const auto again = run_cli({"update", kId});
    CHECK(again.exit_code == 0);
    CHECK(contains(again.stdout_text, "up to date"));

    // --all iterates installed apps (this one is up to date now).
    const auto all = run_cli({"update", "--all"});
    CHECK(all.exit_code == 0);
    CHECK(contains(all.stdout_text, kId));
    CHECK(run_cli({"update", "--all", "--check"}).exit_code == 0);

    // Rollback to the retained previous version…
    const auto rolled = run_cli({"rollback", kId});
    CHECK(rolled.exit_code == 0);
    CHECK(contains(rolled.stdout_text, "1.0.0"));
    CHECK(registry.current_version(kId) == "1.0.0");
    // …and a second rollback has nowhere to go.
    CHECK(run_cli({"rollback", kId}).exit_code == 4);
}

TEST_CASE("update: bad invocations, missing source, --all skips") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();

    CHECK(run_cli({"update"}).exit_code == 2);              // no id, no --all
    CHECK(run_cli({"update", kId, "--all"}).exit_code == 2); // both
    CHECK(run_cli({"update", "com.example.absent"}).exit_code == 4);

    // Installed but no update source configured.
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);
    CHECK(run_cli({"update", kId}).exit_code == 4);

    // --all treats it as a skip, not a failure.
    const auto all = run_cli({"update", "--all"});
    CHECK(all.exit_code == 0);
    CHECK(contains(all.stdout_text, "skipped"));
}

// ------------------------------------------------------------- source set

TEST_CASE("source set records a new update source") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);

    const std::string url = (work.dir / "elsewhere" / "update.json").string();
    const auto r = run_cli({"source", "set", kId, url});
    CHECK(r.exit_code == 0);
    CHECK(Registry(Paths::detect()).read_record(kId).update_url == url);

    CHECK(run_cli({"source", "set", "com.example.absent", url}).exit_code == 4);
    CHECK(run_cli({"source"}).exit_code == 2);              // missing subcommand
    CHECK(run_cli({"source", "get", kId}).exit_code == 2);  // unknown subcommand
    CHECK(run_cli({"source", "set", kId}).exit_code == 2);  // missing url
}

// ------------------------------------------------------------------ remove

TEST_CASE("remove honors the prompt, --yes, and --purge-data") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const fs::path data_file = paths.data_dir() / kId / "save.txt";

    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);
    util::spit(data_file, std::string_view("precious save data\n"));

    // Declined prompt: nothing happens, exit 1.
    const auto declined = run_cli_stdin({"remove", kId}, "n\n", work.dir);
    CHECK(declined.exit_code == 1);
    CHECK(registry.is_installed(kId));

    // Confirmed prompt: removed, but application data survives.
    const auto confirmed = run_cli_stdin({"remove", kId}, "y\n", work.dir);
    CHECK(confirmed.exit_code == 0);
    CHECK_FALSE(registry.is_installed(kId));
    CHECK_FALSE(fs::exists(registry.app_dir(kId)));
    CHECK(fs::is_regular_file(data_file));

    // --purge-data removes the data directory too (FORMAT-0.1 §9).
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);
    const auto purged = run_cli({"remove", kId, "--purge-data", "--yes"});
    CHECK(purged.exit_code == 0);
    CHECK_FALSE(fs::exists(paths.data_dir() / kId));

    CHECK(run_cli({"remove", "com.example.absent", "--yes"}).exit_code == 4);
}

// ------------------------------------------------------------------ repair

TEST_CASE("repair: healthy, repaired from the original package, and "
          "unrepairable -> exit 3") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);

    // Healthy installation.
    const auto healthy = run_cli({"repair", kId});
    CHECK(healthy.exit_code == 0);
    CHECK(contains(healthy.stdout_text, "healthy"));

    // Corrupt an installed payload file; repair restores it from the
    // recorded source package.
    const Registry registry(Paths::detect());
    const fs::path installed =
        registry.version_dir(kId, registry.current_version(kId)) / "data.txt";
    const std::string original = util::slurp_text(installed);
    util::spit(installed, std::string_view("corrupted!"));
    const auto repaired = run_cli({"repair", kId});
    CHECK(repaired.exit_code == 0);
    CHECK(contains(repaired.stdout_text, "Repaired"));
    CHECK(contains(repaired.stdout_text, "payload/data.txt"));
    CHECK(util::slurp_text(installed) == original);

    // Without a usable package the corruption is only reported: exit 3.
    fs::remove(pkg);
    util::spit(installed, std::string_view("corrupted again"));
    CHECK(run_cli({"repair", kId}).exit_code == 3);

    CHECK(run_cli({"repair", "com.example.absent"}).exit_code == 4);
}

// -------------------------------------------------------------- list / misc

TEST_CASE("list on an empty home: friendly text and an empty JSON array") {
    test::TempLexeHome home;
    const auto human = run_cli({"list"});
    CHECK(human.exit_code == 0);
    CHECK(contains(human.stdout_text, "no applications installed"));

    const auto machine = run_cli({"list", "--json"});
    CHECK(machine.exit_code == 0);
    const json j = json::parse(machine.stdout_text);
    CHECK(j.is_array());
    CHECK(j.empty());
}

TEST_CASE("integrate runs and reports what it did") {
    test::TempLexeHome home;
    const auto r = run_cli({"integrate"});
    CHECK(r.exit_code == 0);
#ifdef _WIN32
    CHECK(contains(r.stdout_text, "skipped"));
#else
    CHECK(contains(r.stdout_text, "lexe-installer.desktop"));
    CHECK(fs::is_regular_file(Paths::detect().applications_dir() /
                              "lexe-installer.desktop"));
#endif
}

} // TEST_SUITE("cli")

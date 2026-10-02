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

#include "elf_builder.hpp"
#include "helpers.hpp"

#include "lexe/package/crypto.hpp"
#include "lexe/base/error.hpp"
#include "lexe/package/package.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/base/util.hpp"

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

/// Run `lexe <args…>` CAPTURING STDERR as well as stdout.
///
/// `run_cli` leaves stderr inherited, so `result.stderr_text` is empty for it
/// and every `contains(r.stderr_text, …)` written against it is vacuously true
/// whatever the CLI prints. One such assertion went in earlier in this file
/// before the streams were checked; it is now written against this helper
/// instead. Error messages are half the taxonomy — a caller reads the code and
/// the sentence — so asserting on them needs a helper that actually has them.
util::ProcessResult run_cli_err(const std::vector<std::string>& args) {
    std::vector<std::string> argv{cli_binary().string()};
    argv.insert(argv.end(), args.begin(), args.end());
    util::RunOptions opts;
    opts.capture_stderr = true;
    return util::run_process(argv, opts);
}

#ifndef _WIN32
/// Run `lexe <args…>` with stdin an OPEN PIPE that nobody ever writes to, under
/// a hard wall-clock cap.
///
/// This is the shape `/dev/null` and a closed pipe do NOT reproduce: both of
/// those deliver EOF immediately, so a prompt that is purely EOF-driven looks
/// perfectly well behaved against them and hangs forever against this. A FIFO
/// with a live writer that stays silent is the CI job whose stdin is an
/// inherited pipe.
///
/// `timeout` is what makes the failure legible rather than fatal: a regression
/// here returns 124 after ten seconds instead of wedging the whole suite, so the
/// assertion below can say which outcome it got.
util::ProcessResult run_cli_open_pipe_stdin(const std::vector<std::string>& args,
                                            const fs::path& scratch) {
    static std::atomic<int> counter{0};
    const int n = counter.fetch_add(1);
    const fs::path fifo = scratch / ("openpipe-" + std::to_string(n) + ".fifo");
    const fs::path script = scratch / ("openpipe-" + std::to_string(n) + ".sh");
    std::string text =
        "#!/bin/sh\n"
        "command -v timeout >/dev/null 2>&1 || exit 91\n"
        "command -v mkfifo  >/dev/null 2>&1 || exit 91\n"
        "rm -f \"" + fifo.string() + "\"\n"
        "mkfifo \"" + fifo.string() + "\" || exit 91\n"
        // A writer that holds the pipe open and sends nothing. Its open() and
        // the redirect's open() release each other, which is why neither blocks.
        "sleep 30 > \"" + fifo.string() + "\" &\n"
        "writer=$!\n"
        "timeout 10 \"" + cli_binary().string() + "\"";
    for (const std::string& arg : args) text += " \"" + arg + "\"";
    text += " < \"" + fifo.string() + "\"\n"
            "rc=$?\n"
            "kill \"$writer\" 2>/dev/null\n"
            "rm -f \"" + fifo.string() + "\"\n"
            "exit $rc\n";
    util::spit(script, std::string_view(text));
    std::error_code ec;
    fs::permissions(script, fs::perms::owner_all, fs::perm_options::add, ec);
    util::RunOptions opts;
    opts.capture_stderr = true; // the refusal sentence is part of the claim
    return util::run_process({"/bin/sh", script.string()}, opts);
}
#endif

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

/// Signed package whose entrypoint is a COMPILED native binary that echoes
/// its arguments ("arg: <value>" per line) and exits with `exit_code` —
/// exercises `lexe run` argument forwarding and exit-code propagation.
/// (A native package cannot use a shell script: the verify pipeline's
/// "payload-role" stage requires a real ELF entrypoint.)
fs::path make_exit_code_package(const fs::path& work,
                                const crypto::KeyPair& key,
                                const std::string& id,
                                const std::string& version, int exit_code) {
    test::TestAppSpec spec;
    spec.id = id;
    spec.version = version;
#ifdef _WIN32
    spec.entrypoint = "bin/code.exe";
#else
    spec.entrypoint = "bin/code";
#endif
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree = test::make_test_app_tree(
        work / ("tree-" + id + "-" + version), spec);
    test::write_native_executable(tree.payload_dir / spec.entrypoint,
                                  "code payload " + version, exit_code);
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
    // The tasteful wordmark + tagline heads the help.
    CHECK(contains(r.stdout_text, "Linux applications, made simple."));
    for (const char* command :
         {"install", "run", "update", "uninstall", "purge", "repair", "info", "verify",
          "source set", "rollback", "list", "keygen", "pack", "build",
          "sign-update", "integrate", "analyze", "trust"}) {
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

// --------------------------------------------------------------------- build

TEST_CASE("build turns a project folder into an installable .lexe") {
    test::TempLexeHome home;
    TempWorkDir work;

    // A Lexe project folder: lexe.json (publicKey "AUTO") + payload/.
    const fs::path project = work.dir / "myapp";
    fs::create_directories(project / "payload" / "bin");
    // A native package's entrypoint must be a COMPILED executable — the
    // verify pipeline's payload-role stage rejects scripts and source text.
    test::write_native_executable(project / "payload" / "bin" / "app", "hi");
    util::spit(
        project / "lexe.json",
        std::string_view(
            "{\n  \"lexeVersion\": \"0.1\",\n  \"id\": \"com.example.built\",\n"
            "  \"name\": \"Built\",\n  \"version\": \"1.0.0\",\n"
            "  \"publisher\": { \"name\": \"Me\", \"publicKey\": \"AUTO\" },\n"
            "  \"applicationType\": \"native\",\n"
            "  \"architectures\": [\"x86_64\", \"aarch64\"],\n"
            "  \"entrypoint\": { \"executable\": \"bin/app\" },\n"
            "  \"install\": { \"scope\": \"user\", \"mode\": \"bundled\" }\n}\n"));

    const fs::path out = work.dir / "built.lexe";
    const auto r =
        run_cli({"build", project.string(), "-o", out.string()});
    CHECK(r.exit_code == 0);
    REQUIRE(fs::exists(out));
    // A key was generated in the project and the AUTO publicKey was filled in.
    CHECK(fs::exists(project / "key.json"));
    const json manifest = json::parse(util::slurp_text(project / "lexe.json"));
    const std::string pubkey = manifest["publisher"]["publicKey"];
    CHECK(pubkey.rfind("ed25519:", 0) == 0);

    // The product verifies and installs.
    CHECK(run_cli({"verify", out.string()}).exit_code == 0);
    CHECK(run_cli({"install", out.string(), "--yes"}).exit_code == 0);
    CHECK(Registry(Paths::detect()).is_installed("com.example.built"));

    // Rebuilding with the now-existing key is deterministic.
    const fs::path out2 = work.dir / "built2.lexe";
    REQUIRE(run_cli({"build", project.string(), "-o", out2.string()})
                .exit_code == 0);
    CHECK(util::slurp(out) == util::slurp(out2));
}

TEST_CASE("a build that fails verification names the stage and keeps nothing") {
    // Two defects, both about what a developer is left with.
    //
    // `lexe build` printed "verification:  FAILED" and stopped. The failing
    // stage and its reason were already in the report it had just computed, and
    // it threw them away at the moment they were most wanted -- so the developer
    // had to run `lexe verify` on the artefact to learn what `lexe build` already
    // knew.
    //
    // And it LEFT that artefact on disk, under the name they asked for. The exit
    // code was 3, so a script knew; a person had a plausible-looking .lexe in
    // their output directory, and the next thing anyone does with one of those is
    // send it to somebody.
    test::TempLexeHome home;
    TempWorkDir work;

    // Wrong in exactly one way: the payload is a real host ELF, and the manifest
    // declares only an architecture it is not. This is what a cross-compiling
    // build script produces when it silently falls back to the host compiler.
    const fs::path project = work.dir / "wrongarch";
    fs::create_directories(project / "payload" / "bin");
    test::write_native_executable(project / "payload" / "bin" / "app", "hi");
    // "Not the host" -- the OTHER of the two ISAs, so the case means the same
    // thing on an AArch64 host as on an x86-64 one.
    const std::string other_arch =
        host_architecture() == "aarch64" ? "x86_64" : "aarch64";
    util::spit(
        project / "lexe.json",
        std::string_view(
            "{\n  \"lexeVersion\": \"0.1\",\n  \"id\": \"com.example.wrongarch\",\n"
            "  \"name\": \"Wrong Arch\",\n  \"version\": \"1.0.0\",\n"
            "  \"publisher\": { \"name\": \"Me\", \"publicKey\": \"AUTO\" },\n"
            "  \"applicationType\": \"native\",\n"
            "  \"architectures\": [\"" + other_arch + "\"],\n"
            "  \"entrypoint\": { \"executable\": \"bin/app\" },\n"
            "  \"install\": { \"scope\": \"user\", \"mode\": \"bundled\" }\n}\n"));

    const fs::path out = work.dir / "wrongarch.lexe";
    const auto r = run_cli({"build", project.string(), "-o", out.string()});

    // Exit 3 is the documented verification-failure code.
    CHECK(r.exit_code == 3);

    // It must say WHICH stage, and why.
    INFO(r.stdout_text);
    CHECK(r.stdout_text.find("FAILED") != std::string::npos);
    CHECK(r.stdout_text.find("payload-role") != std::string::npos);
    CHECK(r.stdout_text.find(other_arch) != std::string::npos);

    // And it must not have left the package behind.
    INFO("a package that fails its own verification must not survive the build");
    CHECK_FALSE(fs::exists(out));
}

TEST_CASE("a build that SUCCEEDS still leaves its package") {
    // The counterpart, so the removal above cannot be over-eager: the only thing
    // that gets deleted is a package that failed.
    test::TempLexeHome home;
    TempWorkDir work;
    const fs::path project = work.dir / "fine";
    fs::create_directories(project / "payload" / "bin");
    test::write_native_executable(project / "payload" / "bin" / "app", "hi");
    util::spit(
        project / "lexe.json",
        std::string_view(
            "{\n  \"lexeVersion\": \"0.1\",\n  \"id\": \"com.example.fine\",\n"
            "  \"name\": \"Fine\",\n  \"version\": \"1.0.0\",\n"
            "  \"publisher\": { \"name\": \"Me\", \"publicKey\": \"AUTO\" },\n"
            "  \"applicationType\": \"native\",\n"
            "  \"architectures\": [\"x86_64\", \"aarch64\"],\n"
            "  \"entrypoint\": { \"executable\": \"bin/app\" },\n"
            "  \"install\": { \"scope\": \"user\", \"mode\": \"bundled\" }\n}\n"));

    const fs::path out = work.dir / "fine.lexe";
    CHECK(run_cli({"build", project.string(), "-o", out.string()}).exit_code == 0);
    CHECK(fs::exists(out));
}

TEST_CASE("build rejects a folder that is not a Lexe project") {
    test::TempLexeHome home;
    TempWorkDir work;
    // Missing lexe.json / payload -> runtime error (1).
    fs::create_directories(work.dir / "empty");
    CHECK(run_cli({"build", (work.dir / "empty").string()}).exit_code == 1);
    // Missing directory entirely -> not found (4).
    CHECK(run_cli({"build", (work.dir / "nope").string()}).exit_code == 4);
}

// --------------------------------------------------------------- sign-update

TEST_CASE("sign-update produces a .sig that verifies over the exact bytes") {
    test::TempLexeHome home;
    TempWorkDir work;
    const fs::path keyfile = work.dir / "key.json";
    REQUIRE(run_cli({"keygen", keyfile.string()}).exit_code == 0);
    const crypto::KeyPair key = crypto::read_keyfile(keyfile);

    // Arbitrary update-manifest bytes; sign-update signs bytes, not structure.
    const fs::path update = work.dir / "update.json";
    const std::string body =
        "{ \"lexeVersion\":\"0.1\", \"id\":\"com.example.hello\" }\n";
    util::spit(update, std::string_view(body));

    const auto r = run_cli({"sign-update", update.string(), "--key",
                            keyfile.string()});
    CHECK(r.exit_code == 0);

    // The detached signature is exactly 64 raw bytes (FORMAT-0.1 §7 / §4)...
    const fs::path sig = fs::path(update.string() + ".sig");
    REQUIRE(fs::exists(sig));
    const std::vector<std::uint8_t> sig_bytes = util::slurp(sig);
    REQUIRE(sig_bytes.size() == 64);

    // ...and it verifies over the exact update.json bytes with the publisher
    // key — i.e. exactly what updater.cpp check 1 will do.
    crypto::Signature signature{};
    std::copy(sig_bytes.begin(), sig_bytes.end(), signature.begin());
    const std::vector<std::uint8_t> update_bytes = util::slurp(update);
    CHECK(crypto::verify_signature(update_bytes, signature, key.public_key));

    // A single flipped byte in the document must break verification.
    std::vector<std::uint8_t> tampered = update_bytes;
    tampered[0] ^= 0x01;
    CHECK_FALSE(crypto::verify_signature(tampered, signature, key.public_key));
}

TEST_CASE("sign-update rejects bad invocations") {
    test::TempLexeHome home;
    TempWorkDir work;
    const fs::path keyfile = work.dir / "key.json";
    REQUIRE(run_cli({"keygen", keyfile.string()}).exit_code == 0);
    const fs::path update = work.dir / "update.json";
    util::spit(update, std::string_view("{}"));

    // Missing --key -> usage (2).
    CHECK(run_cli({"sign-update", update.string()}).exit_code == 2);
    // Missing document operand -> usage (2).
    CHECK(run_cli({"sign-update", "--key", keyfile.string()}).exit_code == 2);
    // Nonexistent document -> not-found (4), the CLI's convention for a
    // missing input file (matches `info` on a missing file).
    CHECK(run_cli({"sign-update", (work.dir / "nope.json").string(), "--key",
                   keyfile.string()})
              .exit_code == 4);
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
    REQUIRE(report.at("stages").size() == 7); // no architecture stage
    CHECK(report["stages"][0]["name"] == "structure");
    CHECK(report["stages"][5]["name"] == "hashes");
    CHECK(report["stages"][6]["name"] == "payload-role");
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

    // A path that names NOTHING is 4, not 3. It used to be 3 here, beside the
    // tampered package above, which said "the file was not accepted" about a
    // file that was never opened. See the taxonomy case below for the whole
    // argument and for the distinction from a file that exists and is bad.
    CHECK(run_cli({"verify", (work.dir / "missing.lexe").string()})
              .exit_code == 4);
}

TEST_CASE("a path that names nothing is 4 on every command that takes one, "
          "and never claims the format was violated") {
    test::TempLexeHome home;
    TempWorkDir work;
    const std::string absent = (work.dir / "no-such-file.lexe").string();

    // ERRORS.md §2: NotFoundError is "no such application, file or entry", and
    // "a mistyped path lands here too". These already agreed.
    CHECK(run_cli({"inspect", absent}).exit_code == 4);
    CHECK(run_cli({"analyze", absent}).exit_code == 4);
    CHECK(run_cli({"sdk", "verify", absent}).exit_code == 4);

    // These did not. `verify`, `install` and `open` each ran the §6 pipeline
    // against a file that was not there and reported 3 -- "verification
    // failure, the file was not accepted" -- for which §1 promises that "there
    // is no --force that turns it into an acceptance". That promise is about
    // bytes, and there were none.
    CHECK(run_cli({"verify", absent}).exit_code == 4);
    CHECK(run_cli({"install", absent, "--yes"}).exit_code == 4);
    CHECK(run_cli({"open", absent, "--yes"}).exit_code == 4);

    // And `lexe info` answered 1, the untyped catch-all, with `registry:
    // invalid application id: "<path>"` -- an internal component the user never
    // named, complaining that a documented argument form (`info <file.lexe |
    // id>`) is not the other one.
    // run_cli_err, not run_cli: run_cli leaves stderr inherited, so a
    // `contains(r.stderr_text, …)` written against it is true of any output at
    // all. This assertion was that shape when it was written and proved
    // nothing; the message is half of what changed here, so it is now checked
    // against a helper that has the bytes.
    const auto info = run_cli_err({"info", absent});
    CHECK(info.exit_code == 4);
    CHECK(info.exit_code != 1);
    CHECK_FALSE(info.stderr_text.empty()); // the helper really did capture
    CHECK_FALSE(contains(info.stderr_text, "invalid application id"));
    CHECK(contains(info.stderr_text, "no such package file or installed"));

    // The point is the DISTINCTION, so the neighbouring facts are asserted in
    // the same case: a file that EXISTS and is not a package is still 3, and an
    // App ID that is well-formed but not installed is still 4.
    const fs::path junk = work.dir / "not-a-package.lexe";
    util::spit(junk, std::string_view("this is not a PK archive"));
    CHECK(run_cli({"verify", junk.string()}).exit_code == 3);
    CHECK(run_cli({"install", junk.string(), "--yes"}).exit_code == 3);
    CHECK(run_cli({"info", "com.example.absent"}).exit_code == 4);

    // The machine-readable half. `verify --json <missing>` said
    // `"category":"format-invalid"` -- per ERRORS.md §5, "the package violates
    // Format 0.1, ANY conforming implementation must reject it" -- about a file
    // it had not read. §5 says that field "exists for exactly one decision, and
    // it is the one place where reading the English would give a wrong answer",
    // so the wrong value there is worse than a wrong sentence anywhere else.
    //
    // The document is still produced: a gate gets an answer, not an empty
    // stdout. Only the claim changed.
    const auto missing_json = run_cli({"verify", "--json", absent});
    CHECK(missing_json.exit_code == 4);
    const json mj = json::parse(missing_json.stdout_text);
    CHECK_FALSE(mj.at("ok").get<bool>());
    CHECK(mj.at("failure").at("category") == "not-found");
    CHECK(mj.at("failure").at("category") != "format-invalid");

    // A file that exists and violates §2 still says format-invalid, in this
    // same case, because an assertion that only ever sees "not-found" is
    // satisfied by a runtime that stopped categorising altogether.
    const auto junk_json = run_cli({"verify", "--json", junk.string()});
    CHECK(junk_json.exit_code == 3);
    CHECK(json::parse(junk_json.stdout_text).at("failure").at("category") ==
          "format-invalid");
}

TEST_CASE("verify keeps its OK verdict and exit code but notes that install "
          "would refuse a package whose key conflicts locally") {
    test::TempLexeHome home;
    TempWorkDir work;
    // One App ID, two publisher keys. The second package passes §6 in full and
    // is nevertheless refused outright by `lexe install` (exit 7), because this
    // App ID is bound here to the first key. Before this note, `lexe verify`
    // said "OK" and the user only learned otherwise from the failed install.
    const fs::path installed =
        make_versioned_package(work.dir, test::make_keypair(), "1.0.0");
    const fs::path other =
        make_versioned_package(work.dir, test::make_keypair(), "2.0.0");
    REQUIRE(run_cli({"install", installed.string(), "--yes"}).exit_code == 0);

    const auto human = run_cli({"verify", other.string()});
    // §6 is about the PACKAGE: verdict and exit code are untouched. Exit codes
    // are a documented compatibility promise, and 7 belongs to `lexe install`.
    CHECK(human.exit_code == 0);
    CHECK(contains(human.stdout_text, "verification: OK (signature valid, Ed25519)"));
    // The local consequence, clearly separated from that verdict.
    CHECK(contains(human.stdout_text, "Local trust on this machine"));
    CHECK(contains(human.stdout_text, "NOT part of the verification result above"));
    CHECK(contains(human.stdout_text,
                   "`lexe install` will refuse this package (exit 7)"));
    // Both fingerprints, under the install screen's labels — one alone gives
    // the reader nothing to compare against.
    CHECK(contains(human.stdout_text, "Expected (already installed):"));
    CHECK(contains(human.stdout_text, "Presented (this package):"));
    // The way out is the one the refusal itself names, not a second wording.
    // It used to be two commands (`remove --purge-data` kept the trust record,
    // so `trust forget` had to follow); `purge` forgets both, and the old pair
    // must not survive in this text to send anyone to a retired verb.
    CHECK(contains(human.stdout_text, "lexe purge " + std::string(kId)));
    CHECK_FALSE(contains(human.stdout_text, "--purge-data"));

    const auto machine = run_cli({"verify", other.string(), "--json"});
    CHECK(machine.exit_code == 0);
    const json j = json::parse(machine.stdout_text);
    CHECK(j.at("ok") == true);                  // still the §6 verdict
    CHECK(j.at("signatureState") == "valid");
    CHECK(j.at("localTrust").at("installWouldRefuse") == true);
    CHECK(j.at("localTrust").at("keyState") == "changed");
    CHECK(j.at("localTrust").at("appId") == kId);

    // The note is only useful if it predicts what install really does.
    CHECK(run_cli({"install", other.string(), "--yes"}).exit_code == 7);
}

TEST_CASE("verify says nothing about local trust when there is no conflict") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    // Nothing installed: the App ID is first-seen, install would proceed, and
    // the human screen stays a verification screen.
    const auto fresh = run_cli({"verify", pkg.string()});
    CHECK(fresh.exit_code == 0);
    CHECK_FALSE(contains(fresh.stdout_text, "Local trust on this machine"));
    // --json states it either way, so a script never reads an absent field as
    // consent.
    const json fj = json::parse(
        run_cli({"verify", pkg.string(), "--json"}).stdout_text);
    CHECK(fj.at("localTrust").at("installWouldRefuse") == false);
    CHECK(fj.at("localTrust").at("keyState") == "first-seen");

    // Installed under the SAME key: still no conflict, still no note.
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);
    const auto known = run_cli({"verify", pkg.string()});
    CHECK(known.exit_code == 0);
    CHECK_FALSE(contains(known.stdout_text, "Local trust on this machine"));
    const json kj = json::parse(
        run_cli({"verify", pkg.string(), "--json"}).stdout_text);
    CHECK(kj.at("localTrust").at("keyState") == "known-matching");
    CHECK(kj.at("localTrust").at("installWouldRefuse") == false);

    // A package that does not verify is a §6 failure and nothing else: local
    // trust is moot, and the failure must not be diluted by a second heading.
    test::tamper_entry(pkg, "payload/data.txt",
                       [](std::vector<std::uint8_t>& bytes) {
                           bytes.at(0) ^= 0xFF;
                       });
    const auto bad = run_cli({"verify", pkg.string()});
    CHECK(bad.exit_code == 3);
    CHECK_FALSE(contains(bad.stdout_text, "Local trust on this machine"));
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

TEST_CASE("every CLI location label says which location it is") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path update_json = work.dir / "update.json";
    const fs::path pkg =
        make_versioned_package(work.dir, key, "1.0.0", update_json.string());
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);

    const auto info = run_cli({"info", kId});
    CHECK(info.exit_code == 0);
    // "Source:" is the Installer's label for the packaging MODE, so the CLI
    // must not spend it on a location. This screen prints two DIFFERENT
    // locations on adjacent lines — the package the install came from and the
    // update manifest to check — and an unqualified "Source:" directly above
    // "Update source:" read as though the two described one thing.
    CHECK_FALSE(contains(info.stdout_text, "Source:"));
    CHECK(contains(info.stdout_text, "Installed from:"));
    CHECK(contains(info.stdout_text, pkg.string()));
    CHECK(contains(info.stdout_text, "Update source:"));

    // The human labels say what --json has always called these two fields.
    const json j = json::parse(run_cli({"info", kId, "--json"}).stdout_text);
    CHECK(j.at("installed").at("packageSource") == pkg.string());
    CHECK(j.at("installed").at("updateUrl") == update_json.string());
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

    // Same version again is an OPERATION CONFLICT (exit 6), not the untyped
    // catch-all. docs/ERRORS.md §1 defines 6 as "busy, or an operation
    // conflict" and 1 as "failed for a reason with no more specific code", and
    // "the requested state already holds" is the former.
    //
    // It was 1, which is also what a genuinely broken install returns, so no
    // script could tell "somebody already did this" from "something went
    // wrong" -- and that is the ordinary shape of a provisioning script, and of
    // 22 of 32 concurrent install||install races an independent pass measured.
    const auto again = run_cli({"install", pkg.string(), "--yes"});
    CHECK(again.exit_code == 6);
    CHECK(again.exit_code != 1); // stated separately: the point is the DISTINCTION
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
    // The package's PATH, labelled as a path. A bare "Source:" here named the
    // same thing the Installer's "Source:" block names — the packaging MODE
    // ("Bundled package — all application files are contained in <file>") — so
    // one label stood for two unrelated facts across the two frontends.
    CHECK(contains(yes.stdout_text, "Package file:"));
    CHECK_FALSE(contains(yes.stdout_text, "Source:"));
    CHECK(contains(yes.stdout_text, pkg.string()));
    CHECK(contains(yes.stdout_text, "Application Type:"));
    CHECK(contains(yes.stdout_text, host_architecture()));
    CHECK(contains(yes.stdout_text, "Permissions:"));
    CHECK(contains(yes.stdout_text, "Installation:"));
    CHECK(contains(yes.stdout_text, "Updates:"));
    CHECK(contains(yes.stdout_text, update_json.string()));
    // Truthful trust presentation (WS10): two-dimensional authenticity + local
    // trust with the fingerprint and identity caveat, never a single "verified".
    CHECK(contains(yes.stdout_text, "Authenticity & local trust:"));
    CHECK(contains(yes.stdout_text, "Signing key fingerprint:"));
    CHECK(contains(yes.stdout_text, "not independently verified"));
    CHECK(contains(yes.stdout_text, "first seen"));      // this key is new here
    CHECK(contains(yes.stdout_text, "Isolation on this platform:"));
    CHECK(contains(yes.stdout_text, "[y/N]"));
    CHECK(Registry(Paths::detect()).is_installed(kId));

    REQUIRE(run_cli({"uninstall", kId, "--yes"}).exit_code == 0);

    // Answer "n": cancelled, nothing installed -- and exit 5, "permission or
    // consent required", NOT 0.
    //
    // The original reasoning was that declining is a valid choice rather than a
    // runtime error, which is true and led to the wrong code. Exit 0 from
    // `install` asserts that the application is installed, so
    // `lexe install app.lexe && systemctl restart svc` restarted a service whose
    // new version the user had just refused. docs/ERRORS.md §6 rejected exit 0
    // for an already-current install on exactly that ground; declining is the
    // same claim.
    //
    // 5 says what happened without calling it a failure: consent was required
    // and withheld. That is a documented category, and it keeps "the user said
    // no" distinguishable from "the install was attempted and broke" (1).
    const auto no = run_cli_stdin({"install", pkg.string()}, "n\n", work.dir);
    CHECK(no.exit_code == 5);
    CHECK(no.exit_code != 0); // stated apart: the point is that && does not run on
    CHECK_FALSE(Registry(Paths::detect()).is_installed(kId));

    // EOF on stdin (no answer at all) cancels the same way and reports the same
    // thing. A CI job whose stdin is closed must not be told an install
    // succeeded.
    const auto eof = run_cli_stdin({"install", pkg.string()}, "", work.dir);
    CHECK(eof.exit_code == 5);
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

    // A nonexistent package file is 4, and this case is where the difference is
    // easiest to see: the two invocations sat one line apart and answered the
    // same 3.
    //
    // For the package above, 3 is a verdict -- its payload hash does not match
    // what the publisher signed, and docs/ERRORS.md §1 promises that "the file
    // was not accepted... there is no --force that turns it into an
    // acceptance". For the path below there was no file to render a verdict on,
    // and that promise is about bytes nobody read. ERRORS.md §2 has always put
    // a mistyped path under NotFoundError.
    CHECK(run_cli({"install", (work.dir / "nope.lexe").string(), "--yes"})
              .exit_code == 4);
    // Asserted together, because the point is that they DIFFER: a single
    // expected code is satisfied by an install that answers it for everything.
    CHECK(run_cli({"install", pkg.string(), "--yes"}).exit_code !=
          run_cli({"install", (work.dir / "nope.lexe").string(), "--yes"})
              .exit_code);
}

TEST_CASE("compat --set separates a chain that does not exist from one this "
          "application forbids") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);

    // Both of these used to be exit 1 with the SAME sentence -- "this
    // application's execution policy does not permit the "<x>" chain" -- which
    // for `frobnicate` was a diagnosis of something that never happened. The
    // package has no opinion about `frobnicate`; it is not a chain. Someone who
    // mistyped `box64` was sent to read a manifest.
    const auto absent = run_cli_err({"compat", kId, "--set", "frobnicate"});
    const auto forbidden = run_cli_err({"compat", kId, "--set", "wine"});

    CHECK(absent.exit_code == 4);    // no such chain, anywhere
    CHECK(forbidden.exit_code == 2); // a real chain, excluded by this package
    // The claim is that they DIFFER; either code alone is satisfied by a
    // command that answers it for everything.
    CHECK(absent.exit_code != forbidden.exit_code);
    CHECK(absent.exit_code != 1);
    CHECK(forbidden.exit_code != 1);

    // On both channels, not just the exit status. The identical SENTENCE was
    // half the defect, so the codes alone would not have settled it.
    CHECK_FALSE(absent.stderr_text.empty());
    CHECK(contains(absent.stderr_text, "no such execution chain"));
    CHECK_FALSE(contains(absent.stderr_text, "does not permit"));
    CHECK(contains(forbidden.stderr_text, "does not permit"));
    CHECK(contains(forbidden.stderr_text, "Permitted:"));

    // `lexe runtime show` in this same binary always knew, and still does --
    // that disagreement between two commands about the same word is what made
    // this a defect rather than a wording preference.
    const auto show = run_cli_err({"runtime", "show", "frobnicate"});
    CHECK(show.exit_code == 4);
    CHECK(contains(show.stderr_text, "no such compatibility runtime"));
    // …and its hint no longer leaks the generic NotFoundError fallback. The
    // error names the runtimes it knows; "run `lexe apps` to see installed
    // applications" answered a question nobody asked (docs/ERRORS.md §3).
    CHECK_FALSE(contains(show.stderr_text, "lexe apps"));
    CHECK(contains(show.stderr_text, "lexe runtime list"));

    // A permitted chain still sets, so this is a gate and not a wall.
    const auto ok = run_cli({"compat", kId, "--set", "native"});
    CHECK(contains(ok.stdout_text, "compatibility preference set to \"native\""));
    CHECK(ok.exit_code != 2);
    CHECK(ok.exit_code != 4);
    // And an unknown application is still 4 -- reached before either check.
    CHECK(run_cli({"compat", "com.example.absent", "--set", "native"})
              .exit_code == 4);
}

#ifndef _WIN32
TEST_CASE("the install prompt refuses an input that may never answer, rather "
          "than waiting for it forever") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    // stdin is an OPEN PIPE with a live writer that sends nothing. The prompt
    // was purely EOF-driven with no check on what it was reading from, so this
    // sat in getline; an independent pass measured it still running at 180
    // seconds. /dev/null and a CLOSED pipe both deliver EOF at once and cancel
    // instantly, which is why every obvious test of this looked fine.
    //
    // The helper caps the child at 10 seconds, so a regression here is 124
    // rather than a wedged suite -- and the assertion can then say which of the
    // two it saw instead of never being reached.
    const auto hung = run_cli_open_pipe_stdin({"install", pkg.string()}, work.dir);
    REQUIRE_MESSAGE(hung.exit_code != 91,
                    "BLOCKED: this host has no timeout(1)/mkfifo(1), so the "
                    "hang could not be observed either way");
    CHECK(hung.exit_code != 124); // 124 == still waiting when the cap expired
    // 5, "permission or consent required": consent was required and there was
    // nowhere to obtain it. The same code a declined install returns, so
    // `lexe install app.lexe && systemctl restart svc` behaves identically
    // whether the user said no or could never be asked. Emphatically not 0.
    CHECK(hung.exit_code == 5);
    CHECK_FALSE(Registry(Paths::detect()).is_installed(kId));
    CHECK(contains(hung.stderr_text, "not a terminal"));
    CHECK(contains(hung.stderr_text, "--yes"));

    // The distinctions, in this same case, because "refuse everything" passes
    // every assertion above.
    //
    // 1. --yes still installs with no prompt at all, on that same open pipe.
    const auto yes =
        run_cli_open_pipe_stdin({"install", pkg.string(), "--yes"}, work.dir);
    CHECK(yes.exit_code == 0);
    CHECK(Registry(Paths::detect()).is_installed(kId));
    REQUIRE(run_cli({"uninstall", kId, "--yes"}).exit_code == 0);

    // 2. An answer written down in a FILE is still read and still honoured --
    //    the read is bounded by the file, so it cannot produce the unbounded
    //    wait this is about. Dropping that would have left the consent-accept
    //    path with no automated coverage at all, since the suite has no pty.
    const auto answered = run_cli_stdin({"install", pkg.string()}, "y\n", work.dir);
    CHECK(answered.exit_code == 0);
    CHECK(Registry(Paths::detect()).is_installed(kId));
}
#endif

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
    if (!test::have_native_compiler()) return; // needs a RUNNABLE payload

    // Two apps: one whose payload exits 0, one whose payload exits 42 — a
    // native entrypoint is a compiled binary, so its exit status is baked in
    // rather than taken from an argument.
    const std::string ok_id = "com.example.exitzero";
    const std::string id = "com.example.exitcode";
    const fs::path ok_pkg =
        make_exit_code_package(work.dir, key, ok_id, "1.0.0", 0);
    const fs::path pkg = make_exit_code_package(work.dir, key, id, "1.0.0", 42);
    REQUIRE(run_cli({"install", ok_pkg.string(), "--yes"}).exit_code == 0);
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);

    CHECK(run_cli({"run", ok_id}).exit_code == 0);

    // Everything after `--` reaches the payload verbatim (it echoes its argv).
    const auto forwarded =
        run_cli({"run", ok_id, "--", "7", "two words", "--flag"});
    CHECK(forwarded.exit_code == 0);
    CHECK(contains(forwarded.stdout_text, "arg: 7"));
    CHECK(contains(forwarded.stdout_text, "arg: two words"));
    CHECK(contains(forwarded.stdout_text, "arg: --flag"));

    // A non-zero payload exit propagates through `lexe run`.
    CHECK(run_cli({"run", id}).exit_code == 42);
    CHECK(run_cli({"run", id, "--", "7"}).exit_code == 42);

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

    // Nothing newer: clean no-op with exit 0, and the report ATTRIBUTES its
    // claim to the source.
    //
    // This used to assert the words "up to date". FORMAT-0.1 §7.1 forbids that
    // sentence: "up to date" is a claim about what exists, and what was verified
    // is only what the source offered. 0.1 does not protect update freshness, so
    // a runtime that says "up to date" is reassuring a user about precisely the
    // thing it cannot check. The wording changed deliberately, so the assertion
    // changed with it.
    const auto again = run_cli({"update", kId});
    CHECK(again.exit_code == 0);
    CHECK(contains(again.stdout_text, "no newer version offered"));
    CHECK(contains(again.stdout_text, "update source"));
    INFO("the report must not make an unattributed claim: " << again.stdout_text);
    CHECK_FALSE(contains(again.stdout_text, "up to date"));

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
    // …and a second rollback has nowhere to go: exit 6, an OPERATION CONFLICT,
    // not 4. `rollback <typo>` is 4, so if this were 4 too a script could not
    // tell "fix your App ID" from "this app is installed and there is nothing
    // earlier to return to". Same reasoning as install-already-current in
    // docs/ERRORS.md §6.
    const auto nowhere = run_cli({"rollback", kId});
    CHECK(nowhere.exit_code == 6);
    CHECK(nowhere.exit_code != 4); // the distinction IS the point
    // And the neighbouring fact stays true: an unknown id is still 4.
    CHECK(run_cli({"rollback", "com.example.definitely-not-installed"}).exit_code == 4);
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

TEST_CASE("source set is a positive scheme check, not a two-scheme blocklist") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    // An application must be INSTALLED or every probe below short-circuits on
    // "not installed" (4) without ever reaching the gate — which is how a first
    // measurement of this concluded there was nothing wrong.
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);
    const Registry registry(Paths::detect());

    const std::string good = (work.dir / "good" / "update.json").string();
    REQUIRE(run_cli({"source", "set", kId, good}).exit_code == 0);
    REQUIRE(registry.read_record(kId).update_url == good);

    // The defect. `require_secure_url` called itself an allowlist and was one
    // only for strings containing "://" — so a scheme with a single colon was
    // not seen as a scheme at all, and every one of these was ACCEPTED AND
    // RECORDED as though it were a relative filesystem path.
    for (const char* hostile : {"javascript:alert(1)", "data:text/plain,x",
                                "mailto:someone@example.com", "gopher:x"}) {
        CAPTURE(hostile);
        const auto r = run_cli({"source", "set", kId, hostile});
        CHECK(r.exit_code == 2);
        CHECK(r.exit_code != 0); // it did not merely fail to be refused: it WON
        // The load-bearing assertion. An exit code says what the command
        // claimed; the record says what it did, and the old behaviour stored
        // the value while the exit code was 0.
        CHECK(registry.read_record(kId).update_url == good);
    }

    // The two the blocklist did catch: same refusal, now exit 2 rather than 1
    // (see the ERRORS.md §1/§3 argument at the throw site). The plaintext
    // paragraph is the most useful sentence this command has, and it survives
    // the type change because a throw-site hint outranks every type fallback.
    for (const char* insecure : {"http://example.com/u.json",
                                 "HTTP://example.com/u.json",
                                 "ftp://example.com/u.json"}) {
        CAPTURE(insecure);
        const auto r = run_cli({"source", "set", kId, insecure});
        CHECK(r.exit_code == 2);
        CHECK(registry.read_record(kId).update_url == good);
    }
    // The plaintext paragraph survives the Error -> UsageError change. §3 says
    // UsageError takes no hint from the TYPE fallback; a hint the throw site
    // attached still wins, and this is the most useful sentence the command has.
    const auto plain =
        run_cli_err({"source", "set", kId, "http://example.com/u.json"});
    CHECK_FALSE(plain.stderr_text.empty());
    CHECK(contains(plain.stderr_text, "older signed version"));

    // …and what must still be ACCEPTED, asserted in the same case, because a
    // gate that refuses everything satisfies every assertion above. The
    // refusal's own hint has always promised "an https:// URL, a file:// URL,
    // or a filesystem path", and all three still work. `not-a-url` is a
    // relative path, which is a legitimate thing to configure before it exists;
    // a later `update` names it as a missing source, which is the right error
    // for a path.
    const std::string secure = "https://example.com/u.json";
    CHECK(run_cli({"source", "set", kId, secure}).exit_code == 0);
    CHECK(registry.read_record(kId).update_url == secure);
    const std::string file_url = "file://" + (work.dir / "u.json").string();
    CHECK(run_cli({"source", "set", kId, file_url}).exit_code == 0);
    CHECK(run_cli({"source", "set", kId, "not-a-url"}).exit_code == 0);
    CHECK(run_cli({"source", "set", kId, "./relative/u.json"}).exit_code == 0);
    CHECK(run_cli({"source", "set", kId, good}).exit_code == 0);
    CHECK(registry.read_record(kId).update_url == good);
}

// ------------------------------------------------------- uninstall / purge

TEST_CASE("uninstall honors the prompt and --yes; purge forgets the App ID") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const fs::path data_file = paths.data_dir() / kId / "save.txt";

    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);
    util::spit(data_file, std::string_view("precious save data\n"));

    // Declined prompt: nothing happens; declining is not an error, so exit 0.
    const auto declined = run_cli_stdin({"uninstall", kId}, "n\n", work.dir);
    CHECK(declined.exit_code == 0);
    CHECK(registry.is_installed(kId));

    // Confirmed prompt: removed, but application data survives.
    const auto confirmed = run_cli_stdin({"uninstall", kId}, "y\n", work.dir);
    CHECK(confirmed.exit_code == 0);
    CHECK_FALSE(registry.is_installed(kId));
    CHECK_FALSE(fs::exists(registry.app_dir(kId)));
    CHECK(fs::is_regular_file(data_file));

    // Removing it AGAIN is an operation conflict (6), not a lookup failure (4).
    //
    // Both cases used to be 4 with the identical sentence "application not
    // installed: <id>", so a caller could separate "fix your App ID" from "this
    // machine already removed that application" on neither channel it can read
    // -- and the second is the position the loser of every
    // `uninstall||uninstall` race is in. Same category and same argument as
    // install-already-current (docs/ERRORS.md §6) and rollback-with-nowhere-to-go.
    //
    // Two witnesses, each tested ALONE, because a case that only ever has both
    // holds one of them constant and so cannot tell whether reading it works.
    SUBCASE("witness: retained data alone (trust record forgotten)") {
        REQUIRE(run_cli({"trust", "forget", kId, "--force"}).exit_code == 0);
        const auto again = run_cli({"uninstall", kId, "--yes"});
        CHECK(again.exit_code == 6);
        CHECK(again.exit_code != 4); // stated apart: the DISTINCTION is the point
        CHECK(fs::is_regular_file(data_file)); // and it removed nothing
    }
    SUBCASE("witness: trust record alone (data directory gone)") {
        fs::remove_all(paths.data_dir() / kId);
        REQUIRE_FALSE(registry.has_retained_data(kId));
        CHECK(run_cli({"uninstall", kId, "--yes"}).exit_code == 6);
    }
    SUBCASE("purge removes both witnesses, so the App ID is unknown again") {
        // Purge works on an application that is NOT installed: what uninstall
        // kept is exactly what it exists to remove. (The old `remove
        // --purge-data` refused here with "nothing to remove", so retained data
        // could not be purged from the CLI at all once the app was gone.)
        const auto purged = run_cli({"purge", kId, "--yes"});
        CHECK(purged.exit_code == 0);
        CHECK_FALSE(fs::exists(paths.data_dir() / kId));
        CHECK_FALSE(fs::exists(registry.trust_record_file(kId)));
        // After a purge nothing here can show it was ever installed: 4, the
        // never-installed answer, which is the point of forgetting it.
        CHECK(run_cli({"uninstall", kId, "--yes"}).exit_code == 4);
        // And a second purge has nothing to do: 4 as well.
        CHECK(run_cli({"purge", kId, "--yes"}).exit_code == 4);
    }

    // An App ID this machine never installed is 4, in this same case, because
    // `CHECK(rc == 6)` on its own is satisfied by an `uninstall` that always
    // answers 6.
    CHECK(run_cli({"uninstall", "com.example.absent", "--yes"}).exit_code == 4);
}

TEST_CASE("`lexe remove` is retired: a usage error that names both replacements") {
    test::TempLexeHome home;
    // Not an alias, on purpose: `remove --purge-data` kept the trust record and
    // `purge` deletes it, so an alias would change what an old script does.
    for (const std::vector<std::string>& argv :
         {std::vector<std::string>{"remove", "com.example.any"},
          std::vector<std::string>{"remove", "com.example.any", "--purge-data",
                                   "--yes"}}) {
        // run_cli_err, not run_cli: run_cli leaves stderr uncaptured, and an
        // assertion on its empty stderr_text proves nothing either way.
        const auto r = run_cli_err(argv);
        CHECK(r.exit_code == 2);
        CHECK(contains(r.stderr_text, "lexe uninstall <id>"));
        CHECK(contains(r.stderr_text, "lexe purge <id>"));
    }
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

TEST_CASE("integrate registers a PERSISTENT .lexe handler") {
    // Definitive Architecture §14.1: the handler is installed SYSTEM STATE,
    // not session state. `integrate` must therefore write a handler entry, a
    // MIME declaration AND a durable default association, and record all of it
    // so `doctor` can verify and repair it later.
    test::TempLexeHome home;
    const auto r = run_cli({"integrate"});
    CHECK(r.exit_code == 0);
#ifdef _WIN32
    CHECK(contains(r.stdout_text, "skipped"));
#else
    const Paths paths = Paths::detect();
    CHECK(contains(r.stdout_text, "lexe-handler.desktop"));
    CHECK(contains(r.stdout_text, "application/vnd.usha.lexe"));
    CHECK(fs::is_regular_file(paths.applications_dir() /
                              "lexe-handler.desktop"));
    CHECK(fs::is_regular_file(paths.mime_dir() / "packages" / "lexe.xml"));

    // The association is the part that actually survives a reboot.
    REQUIRE(fs::is_regular_file(paths.mimeapps_file()));
    const std::string mimeapps = util::slurp_text(paths.mimeapps_file());
    CHECK(contains(mimeapps, "[Default Applications]"));
    CHECK(contains(mimeapps,
                   "application/vnd.usha.lexe=lexe-handler.desktop"));
    // The alpha's type stays registered as an alias so existing files and
    // already-registered desktops keep working.
    CHECK(contains(mimeapps, "application/x-lexe=lexe-handler.desktop"));
    const std::string mime_xml =
        util::slurp_text(paths.mime_dir() / "packages" / "lexe.xml");
    CHECK(contains(mime_xml, "application/vnd.usha.lexe"));
    CHECK(contains(mime_xml, "<alias type=\"application/x-lexe\"/>"));

    // The handler must route through .LEXE, never through a payload path.
    const std::string entry =
        util::slurp_text(paths.applications_dir() / "lexe-handler.desktop");
    CHECK(contains(entry, "Exec=lexe-ui --open %f"));

    // And it must be recorded, so doctor reports a healthy system.
    CHECK(fs::is_regular_file(paths.integration_state_file()));
    const auto doctor = run_cli({"doctor"});
    CHECK(doctor.exit_code == 0);
    CHECK(contains(doctor.stdout_text, "healthy"));
#endif
}

TEST_CASE("doctor detects and repairs a broken .lexe handler registration") {
#ifndef _WIN32
    // The alpha's defining failure: it worked, then after a reboot it did not.
    // Whatever destroys the registration, `doctor` must NAME it and `doctor
    // --repair` must re-establish it (§14.1, §15.1).
    test::TempLexeHome home;
    REQUIRE(run_cli({"integrate"}).exit_code == 0);
    const Paths paths = Paths::detect();

    const fs::path handler =
        paths.applications_dir() / "lexe-handler.desktop";
    REQUIRE(fs::is_regular_file(handler));
    fs::remove(handler);
    fs::remove(paths.mimeapps_file());

    const auto broken = run_cli({"doctor"});
    CHECK(broken.exit_code != 0);
    CHECK(contains(broken.stdout_text, "lexe-handler.desktop"));
    CHECK(contains(broken.stdout_text, "missing"));

    const auto repaired = run_cli({"doctor", "--repair"});
    CHECK(repaired.exit_code == 0);
    CHECK(fs::is_regular_file(handler));
    CHECK(contains(util::slurp_text(paths.mimeapps_file()),
                   "application/vnd.usha.lexe=lexe-handler.desktop"));

    // And a second check now passes.
    CHECK(run_cli({"doctor"}).exit_code == 0);
#endif
}

TEST_CASE("trust commands: show / block / unblock / forget over the CLI") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);

    // show: a known key, never presented as externally verified.
    const auto show = run_cli({"trust", "show", kId});
    CHECK(show.exit_code == 0);
    CHECK(contains(show.stdout_text, "Local trust"));
    CHECK(contains(show.stdout_text, "known key"));
    CHECK(contains(show.stdout_text, "real-world identity"));

    const auto show_json = run_cli({"trust", "show", kId, "--json"});
    CHECK(show_json.exit_code == 0);
    const json j = json::parse(show_json.stdout_text);
    CHECK(j.at("appId") == kId);
    CHECK(j.at("localKeyState") == "known");
    CHECK(j.at("identityVerified") == false);
    CHECK(j.at("fingerprint").at("full").get<std::string>().size() == 64);

    // block: install, update and launch are all refused (exit 7).
    CHECK(run_cli({"trust", "block", kId}).exit_code == 0);
    CHECK(run_cli({"run", kId}).exit_code == 7);
    CHECK(run_cli({"install", pkg.string(), "--yes"}).exit_code == 7);

    // unblock restores normal operation.
    CHECK(run_cli({"trust", "unblock", kId}).exit_code == 0);
    if (test::have_native_compiler()) { // else the payload is not runnable
        CHECK(run_cli({"run", kId}).exit_code == 0);
    }

    // forget is refused while the app is installed (usage error), unless forced.
    CHECK(run_cli({"trust", "forget", kId}).exit_code == 2);
    CHECK(run_cli({"trust", "forget", kId, "--force"}).exit_code == 0);
    // After forget, show reports there is no record (a package would be first-seen).
    CHECK(contains(run_cli({"trust", "show", kId}).stdout_text, "no record"));

    // unblock with nothing to unblock is a not-found (exit 4).
    CHECK(run_cli({"trust", "unblock", "com.example.nobody"}).exit_code == 4);
    // an unknown subcommand is a usage error.
    CHECK(run_cli({"trust", "frobnicate", kId}).exit_code == 2);
}

TEST_CASE("info and verify expose the signing-key fingerprint and trust state") {
    test::TempLexeHome home;
    TempWorkDir work;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    // verify --json: authenticity dimension + fingerprint, identity NOT verified.
    const auto vj = run_cli({"verify", pkg.string(), "--json"});
    CHECK(vj.exit_code == 0);
    const json v = json::parse(vj.stdout_text);
    CHECK(v.at("signatureState") == "valid");
    CHECK(v.at("identityVerified") == false);
    CHECK(v.at("fingerprint").at("full").get<std::string>().size() == 64);
    CHECK(contains(run_cli({"verify", pkg.string()}).stdout_text,
                   "real-world identity"));

    // info on a package file exposes the fingerprint.
    const json pj = json::parse(run_cli({"info", pkg.string(), "--json"}).stdout_text);
    CHECK(pj.at("identityVerified") == false);
    CHECK(pj.at("fingerprint").at("full").get<std::string>().size() == 64);

    // installed info exposes the local trust state.
    REQUIRE(run_cli({"install", pkg.string(), "--yes"}).exit_code == 0);
    const json ins = json::parse(run_cli({"info", kId, "--json"}).stdout_text);
    CHECK(ins.at("localTrust").at("state") == "known");
    CHECK(ins.at("localTrust").at("identityVerified") == false);
    CHECK(ins.at("localTrust").at("blocked") == false);
}

TEST_CASE("analyze reports dependency classification and compatibility") {
    test::TempLexeHome home;
    TempWorkDir work;

    // A payload: an app that needs a host lib, a bundled lib (present), a
    // forbidden GPU interface, and an unresolved lib.
    test::ElfSpec lib;
    lib.soname = "libcustom.so.1";
    test::write_elf(work.dir / "libcustom.so.1", lib);
    test::ElfSpec app;
    app.interp = "/lib64/ld-linux-x86-64.so.2";
    app.needed = {"libc.so.6", "libcustom.so.1", "libGL.so.1", "libmystery.so.9"};
    const fs::path root = work.dir / "app";
    test::write_elf(root, app);

    const auto human = run_cli({"analyze", root.string()});
    // This fixture declares `libmystery.so.9`, which exists nowhere, so its
    // runtime contract genuinely is not satisfied -- exit 3, like `sdk verify`
    // and `verify`. `analyze` used to return 0 unconditionally, which meant
    // every scripted pre-ship gate passed the packages it exists to catch.
    CHECK(human.exit_code == 3);
    CHECK(contains(human.stdout_text, "Dependencies:"));
    CHECK(contains(human.stdout_text, "libcustom.so.1"));
    CHECK(contains(human.stdout_text, "Compatibility:"));
    CHECK(contains(human.stdout_text, "Runtime contract: NOT satisfied"));

    const auto j = run_cli({"analyze", root.string(), "--json"});
    CHECK(j.exit_code == 3);
    const json doc = json::parse(j.stdout_text);
    CHECK(doc.at("runtimeProfile") == "core-portable");
    CHECK(doc.at("dependencySummary").at("forbidden") == 1);
    CHECK(doc.at("dependencySummary").at("unresolved") == 1);
    CHECK(doc.at("dependencySummary").at("hostInterface") == 1);
    CHECK(doc.at("runtimeContract").at("satisfied") == false);

    // And the case that must NOT exit 3, because a check that condemns
    // everything is indistinguishable from a broken one. Same fixture minus the
    // dependency that exists nowhere: a host interface and a bundled library the
    // analysis can see, so the contract holds.
    test::ElfSpec fine;
    fine.interp = "/lib64/ld-linux-x86-64.so.2";
    fine.needed = {"libc.so.6"};
    const fs::path ok_root = work.dir / "app-ok";
    test::write_elf(ok_root, fine);
    const auto okr = run_cli({"analyze", ok_root.string(), "--json"});
    CHECK(okr.exit_code == 0);
    CHECK(json::parse(okr.stdout_text).at("runtimeContract").at("satisfied") ==
          true);

    // --profile selects a profile; a bad profile is a usage error.
    const auto nc =
        run_cli({"analyze", root.string(), "--profile", "native-capture", "--json"});
    CHECK(json::parse(nc.stdout_text).at("runtimeProfile") == "native-capture");
    CHECK(run_cli({"analyze", root.string(), "--profile", "bogus"}).exit_code == 2);

    // A non-ELF target is a clean error, not a crash.
    const fs::path text = work.dir / "readme.txt";
    util::spit(text, std::string_view("hello"));
    CHECK(run_cli({"analyze", text.string()}).exit_code != 0);
}

} // TEST_SUITE("cli")

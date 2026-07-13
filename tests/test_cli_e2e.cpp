// cli_e2e — end-to-end product proof (ARCHITECTURE.md #Tests). Drives the
// BUILT `lexe` binary as a subprocess through the complete product lifecycle:
//
//   keygen -> pack -> verify -> info --json -> install --yes -> list --json
//   -> run (exit-code propagation) -> source set + update via file://
//   (new version packed in-test) -> rollback -> remove
//
// After every step the registry state is asserted ON DISK (FORMAT-0.1 §9):
// installation.json is parsed as raw JSON, the current pointer is resolved by
// reading the `current` symlink / `current.txt` fallback directly, and the
// versions/<v>/ trees are stat'ed — no shortcut through the Registry class
// for the assertions that matter.
//
// The CLI binary is located via the LEXE_TEST_BINARY environment variable
// (set by CTest), then LEXE_CLI, then the LEXE_TEST_BINARY_PATH compile
// definition, then `lexe(.exe)` next to the test executable.
//
// Every test case constructs lexe::test::TempLexeHome first, so LEXE_HOME
// always points into a fresh temp directory; child processes inherit it.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include <cctype>
#include <filesystem>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;
using nlohmann::json;

namespace {

constexpr const char* kId = "com.example.e2e";

/// RAII scratch directory for trees/packages/keys, OUTSIDE LEXE_HOME.
struct TempWorkDir {
    fs::path dir;
    TempWorkDir() : dir(test::unique_temp_dir("lexe-e2e-work-")) {
        fs::create_directories(dir);
    }
    ~TempWorkDir() {
        std::error_code ec;
        fs::remove_all(dir, ec); // best effort
    }
    TempWorkDir(const TempWorkDir&) = delete;
    TempWorkDir& operator=(const TempWorkDir&) = delete;
};

/// Directory containing this test executable (last-resort CLI location).
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
    for (const char* var : {"LEXE_TEST_BINARY", "LEXE_CLI"}) {
        if (const auto env = util::get_env(var);
            env.has_value() && !env->empty()) {
            return fs::path(*env);
        }
    }
#ifdef LEXE_TEST_BINARY_PATH
    {
        const fs::path baked(LEXE_TEST_BINARY_PATH);
        std::error_code ec;
        if (fs::is_regular_file(baked, ec)) return baked;
    }
#endif
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

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// -------------------------------------------------- on-disk registry probes

/// <LEXE_HOME>/apps/<id> — built from the raw environment, on purpose.
fs::path app_dir_on_disk(const std::string& id) {
    const auto home = util::get_env("LEXE_HOME");
    REQUIRE(home.has_value());
    return fs::path(*home) / "apps" / id;
}

/// Resolve the current pointer straight from disk: the `current` symlink
/// target's filename, else the trimmed contents of `current.txt`
/// (FORMAT-0.1 §9). nullopt when neither exists.
std::optional<std::string> current_on_disk(const std::string& id) {
    const fs::path app = app_dir_on_disk(id);
    std::error_code ec;
    const fs::path link = app / "current";
    if (fs::is_symlink(link, ec)) {
        const fs::path target = fs::read_symlink(link, ec);
        if (!ec) return target.filename().string();
    }
    const fs::path txt = app / "current.txt";
    if (fs::is_regular_file(txt, ec)) {
        std::string text = util::slurp_text(txt);
        while (!text.empty() &&
               std::isspace(static_cast<unsigned char>(text.back())) != 0) {
            text.pop_back();
        }
        return text;
    }
    return std::nullopt;
}

/// Parse apps/<id>/installation.json from disk (raw JSON, not the Registry).
json record_on_disk(const std::string& id) {
    return json::parse(util::slurp_text(app_dir_on_disk(id) /
                                        "installation.json"));
}

// ------------------------------------------------------------- app fixture

/// Unpacked source tree for the e2e app: a payload whose entrypoint exits
/// with its first argument (default 0) after printing a marker, plus a
/// FORMAT-0.1 §5 lexe.json carrying `public_key` and (optionally) an updates
/// block pointing at `update_url`.
struct E2eTree {
    fs::path payload_dir;
    fs::path manifest_file;
};

E2eTree make_e2e_tree(const fs::path& root, const std::string& version,
                      const std::string& public_key,
                      const std::string& update_url) {
    E2eTree tree;
    tree.payload_dir = root / "payload";
    tree.manifest_file = root / "lexe.json";

    util::spit(tree.payload_dir / "bin" / "app.sh",
               std::string_view("#!/bin/sh\necho e2e app " + version +
                                "\nexit \"${1:-0}\"\n"));
    util::spit(tree.payload_dir / "bin" / "app.cmd",
               std::string_view("@echo e2e app " + version +
                                "\r\n@exit /b %1\r\n"));
    util::spit(tree.payload_dir / "share" / "version.txt",
               std::string_view(version + "\n"));
#ifndef _WIN32
    std::error_code ec;
    fs::permissions(tree.payload_dir / "bin" / "app.sh",
                    fs::perms::owner_all | fs::perms::group_read |
                        fs::perms::others_read,
                    fs::perm_options::replace, ec);
#endif

#ifdef _WIN32
    const std::string entrypoint = "bin/app.cmd";
#else
    const std::string entrypoint = "bin/app.sh";
#endif
    json manifest = {
        {"lexeVersion", "0.1"},
        {"id", kId},
        {"name", "E2E App"},
        {"version", version},
        {"publisher",
         {{"name", "E2E Publisher"}, {"publicKey", public_key}}},
        {"applicationType", "native"},
        {"architectures", json::array({"x86_64", "aarch64"})},
        {"entrypoint",
         {{"executable", entrypoint}, {"arguments", json::array()}}},
        {"install", {{"scope", "user"}, {"mode", "bundled"}}},
        {"permissions", json::array({"network"})},
    };
    if (!update_url.empty()) {
        manifest["updates"] = {{"enabled", true},
                               {"channel", "stable"},
                               {"manifest", update_url},
                               {"allowSourceChange", true}};
    }
    util::spit(tree.manifest_file, std::string_view(manifest.dump(2) + "\n"));
    return tree;
}

/// Pack a version of the e2e app THROUGH THE CLI. Returns the package path.
fs::path pack_via_cli(const fs::path& work, const fs::path& keyfile,
                      const std::string& public_key,
                      const std::string& version,
                      const std::string& update_url = "") {
    const E2eTree tree =
        make_e2e_tree(work / ("tree-" + version), version, public_key,
                      update_url);
    const fs::path out = work / (std::string(kId) + "-" + version + ".lexe");
    const auto r = run_cli({"pack", tree.payload_dir.string(), "--manifest",
                            tree.manifest_file.string(), "--key",
                            keyfile.string(), "-o", out.string()});
    REQUIRE(r.exit_code == 0);
    REQUIRE(fs::is_regular_file(out));
    return out;
}

/// `path` as a file:// URL (FORMAT-0.1 §7 — the runtime accepts file://;
/// this is what the update flow is exercised through). Spaces are the only
/// bytes a temp path plausibly contains that need escaping.
std::string to_file_url(const fs::path& path) {
    std::string generic = path.generic_string();
    std::string encoded;
    encoded.reserve(generic.size());
    for (const char c : generic) {
        if (c == ' ') {
            encoded += "%20";
        } else {
            encoded += c;
        }
    }
    if (!encoded.empty() && encoded.front() == '/') {
        return "file://" + encoded;   // POSIX: file:///home/…
    }
    return "file:///" + encoded;      // Windows: file:///C:/…
}

/// Write update.json + detached .sig (FORMAT-0.1 §7) advertising `package`
/// at `version` on the stable channel, signed with `key`.
fs::path write_update_manifest(const fs::path& work,
                               const crypto::KeyPair& key,
                               const std::string& version,
                               const fs::path& package) {
    const json update = {
        {"lexeVersion", "0.1"},
        {"id", kId},
        {"channels",
         {{"stable",
           {{"version", version},
            {"package",
             {{"url", package.string()},
              {"sha256", crypto::sha256_file_hex(package)}}},
            {"minimumRuntime", "0.1"}}}}},
    };
    const std::string text = update.dump(2);
    const fs::path file = work / "update.json";
    util::spit(file, std::string_view(text));
    const std::vector<std::uint8_t> bytes(text.begin(), text.end());
    const crypto::Signature sig = crypto::sign(bytes, key);
    util::spit(fs::path(file.string() + ".sig"), sig.data(), sig.size());
    return file;
}

} // namespace

TEST_SUITE("cli_e2e") {

TEST_CASE("full product lifecycle: keygen -> pack -> verify -> info -> "
          "install -> list -> run -> source set + update (file://) -> "
          "rollback -> remove") {
    test::TempLexeHome home;
    TempWorkDir work;

    // ------------------------------------------------------------- keygen
    const fs::path keyfile = work.dir / "publisher-key.json";
    {
        const auto r = run_cli({"keygen", keyfile.string()});
        REQUIRE(r.exit_code == 0);
        REQUIRE(fs::is_regular_file(keyfile));
    }
    const json keydoc = json::parse(util::slurp_text(keyfile));
    const std::string public_key = keydoc.at("publicKey").get<std::string>();
    CHECK(keydoc.at("algorithm").get<std::string>() == "ed25519");
    CHECK(public_key.rfind("ed25519:", 0) == 0);
    // Nothing installed yet: no registry directory for the app.
    CHECK_FALSE(fs::exists(app_dir_on_disk(kId)));

    // Loaded only for signing update.json later — the flow itself is CLI-only.
    const crypto::KeyPair key = crypto::read_keyfile(keyfile);

    // --------------------------------------------------------------- pack
    const fs::path pkg1 = pack_via_cli(work.dir, keyfile, public_key, "1.0.0");
    // FORMAT-0.1 §1: deterministic — packing the identical tree again is
    // byte-identical (tree contents don't depend on the tree path).
    {
        TempWorkDir again;
        const fs::path pkg1b =
            pack_via_cli(again.dir, keyfile, public_key, "1.0.0");
        CHECK(util::slurp(pkg1) == util::slurp(pkg1b));
    }

    // ------------------------------------------------------------- verify
    {
        const auto r = run_cli({"verify", pkg1.string()});
        CHECK(r.exit_code == 0);
        CHECK(contains(r.stdout_text, "OK"));
        // Machine-readable report: all six pre-install stages green.
        const auto rj = run_cli({"verify", pkg1.string(), "--json"});
        CHECK(rj.exit_code == 0);
        const json report = json::parse(rj.stdout_text);
        CHECK(report.at("ok").get<bool>());
        REQUIRE(report.at("stages").size() == 6);
        for (const auto& stage : report["stages"]) {
            CHECK(stage.at("ok").get<bool>());
        }
    }

    // -------------------------------------------------------- info --json
    {
        const auto r = run_cli({"info", pkg1.string(), "--json"});
        CHECK(r.exit_code == 0);
        const json j = json::parse(r.stdout_text);
        CHECK(j.at("source") == "package");
        CHECK(j.at("manifest").at("id") == kId);
        CHECK(j.at("manifest").at("version") == "1.0.0");
        CHECK(j.at("manifest").at("publisher").at("publicKey") == public_key);
    }
    // Still nothing on disk: info/verify are read-only.
    CHECK_FALSE(fs::exists(app_dir_on_disk(kId)));

    // ------------------------------------------------------ install --yes
    {
        const auto r = run_cli({"install", pkg1.string(), "--yes"});
        REQUIRE(r.exit_code == 0);
        CHECK(contains(r.stdout_text, kId));
    }
    const fs::path app_dir = app_dir_on_disk(kId);
    {
        // FORMAT-0.1 §9 layout, asserted directly on disk.
        REQUIRE(fs::is_directory(app_dir / "versions" / "1.0.0"));
        CHECK(fs::is_regular_file(app_dir / "versions" / "1.0.0" / "share" /
                                  "version.txt"));
        CHECK(util::slurp_text(app_dir / "versions" / "1.0.0" / "share" /
                               "version.txt") == "1.0.0\n");
        CHECK(fs::is_regular_file(app_dir / "manifest.json"));
        CHECK(json::parse(util::slurp_text(app_dir / "manifest.json"))
                  .at("version") == "1.0.0");
        REQUIRE(current_on_disk(kId).has_value());
        CHECK(*current_on_disk(kId) == "1.0.0");

        const json rec = record_on_disk(kId);
        CHECK(rec.at("id") == kId);
        CHECK(rec.at("version") == "1.0.0");
        CHECK(rec.at("source") == pkg1.string());
        CHECK(rec.at("publisherKey") == public_key);
        CHECK(rec.at("channel") == "stable");
        CHECK(rec.at("updateUrl").get<std::string>().empty()); // none yet
        CHECK_FALSE(rec.at("installedAtUtc").get<std::string>().empty());
        CHECK(rec.at("lastRun").is_null()); // never run yet (§9)
        CHECK(rec.at("createdFiles").is_array());
#ifndef _WIN32
        // Installer restores the entrypoint exec bit (ZIP mode bits are not
        // preserved by the deterministic writer).
        const fs::perms perms =
            fs::status(app_dir / "versions" / "1.0.0" / "bin" / "app.sh")
                .permissions();
        CHECK((perms & fs::perms::owner_exec) != fs::perms::none);
#endif
    }

    // --------------------------------------------------------- list --json
    {
        const auto r = run_cli({"list", "--json"});
        CHECK(r.exit_code == 0);
        const json apps = json::parse(r.stdout_text);
        REQUIRE(apps.is_array());
        REQUIRE(apps.size() == 1);
        CHECK(apps[0].at("id") == kId);
        CHECK(apps[0].at("version") == "1.0.0");
    }

    // ------------------------------------------- run (exit-code propagation)
    {
        CHECK(run_cli({"run", kId}).exit_code == 0);
        CHECK(run_cli({"run", kId, "--", "5"}).exit_code == 5);
        CHECK(run_cli({"run", kId, "--", "41"}).exit_code == 41);

        // lastRun {at, exitCode} lands in installation.json on disk (§9).
        const json rec = record_on_disk(kId);
        REQUIRE(rec.at("lastRun").is_object());
        CHECK(rec["lastRun"].at("exitCode").get<int>() == 41);
        CHECK_FALSE(rec["lastRun"].at("at").get<std::string>().empty());
    }

    // -------------------------------- source set + update via file:// URL
    const fs::path pkg2 =
        pack_via_cli(work.dir, keyfile, public_key, "1.1.0");
    const fs::path update_json =
        write_update_manifest(work.dir, key, "1.1.0", pkg2);
    const std::string update_url = to_file_url(update_json);
    {
        const auto r = run_cli({"source", "set", kId, update_url});
        CHECK(r.exit_code == 0);
        CHECK(record_on_disk(kId).at("updateUrl") == update_url);
        // Registry otherwise untouched.
        CHECK(*current_on_disk(kId) == "1.0.0");
    }
    {
        // Dry run first: reports the newer version, changes nothing on disk.
        const auto check = run_cli({"update", kId, "--check"});
        CHECK(check.exit_code == 0);
        CHECK(contains(check.stdout_text, "1.1.0"));
        CHECK(*current_on_disk(kId) == "1.0.0");
        CHECK_FALSE(fs::exists(app_dir / "versions" / "1.1.0"));

        // Apply: 1.0.0 -> 1.1.0.
        const auto r = run_cli({"update", kId});
        REQUIRE(r.exit_code == 0);
        REQUIRE(current_on_disk(kId).has_value());
        CHECK(*current_on_disk(kId) == "1.1.0");
        REQUIRE(fs::is_directory(app_dir / "versions" / "1.1.0"));
        CHECK(util::slurp_text(app_dir / "versions" / "1.1.0" / "share" /
                               "version.txt") == "1.1.0\n");
        // The previous version is retained for rollback (§7).
        CHECK(fs::is_directory(app_dir / "versions" / "1.0.0"));

        const json rec = record_on_disk(kId);
        CHECK(rec.at("version") == "1.1.0");
        CHECK(rec.at("publisherKey") == public_key); // pinned key unchanged
        CHECK(rec.at("updateUrl") == update_url);    // user source preserved
        // manifest.json now describes the active version.
        CHECK(json::parse(util::slurp_text(app_dir / "manifest.json"))
                  .at("version") == "1.1.0");

        // The updated app actually runs (and still propagates exit codes).
        CHECK(run_cli({"run", kId, "--", "7"}).exit_code == 7);

        // Nothing newer now: clean no-op, registry unchanged.
        CHECK(run_cli({"update", kId}).exit_code == 0);
        CHECK(*current_on_disk(kId) == "1.1.0");
    }

    // ------------------------------------------------------------ rollback
    {
        const auto r = run_cli({"rollback", kId});
        CHECK(r.exit_code == 0);
        REQUIRE(current_on_disk(kId).has_value());
        CHECK(*current_on_disk(kId) == "1.0.0");
        CHECK(record_on_disk(kId).at("version") == "1.0.0");
        CHECK(json::parse(util::slurp_text(app_dir / "manifest.json"))
                  .at("version") == "1.0.0");
        // Both version trees still on disk after the flip.
        CHECK(fs::is_directory(app_dir / "versions" / "1.0.0"));
        CHECK(fs::is_directory(app_dir / "versions" / "1.1.0"));
        // And the rolled-back version is the one that runs.
        CHECK(run_cli({"run", kId, "--", "3"}).exit_code == 3);
    }

    // -------------------------------------------------------------- remove
    {
        const auto r = run_cli({"remove", kId, "--yes"});
        CHECK(r.exit_code == 0);
        // FORMAT-0.1 §9: the whole app directory is gone.
        CHECK_FALSE(fs::exists(app_dir));

        const auto listed = run_cli({"list", "--json"});
        CHECK(listed.exit_code == 0);
        const json apps = json::parse(listed.stdout_text);
        CHECK(apps.is_array());
        CHECK(apps.empty());

        // Everything after removal treats the id as not installed (exit 4).
        CHECK(run_cli({"run", kId}).exit_code == 4);
        CHECK(run_cli({"rollback", kId}).exit_code == 4);
    }
}

TEST_CASE("update refuses a wrong-key update manifest and a tampered "
          "package end-to-end") {
    test::TempLexeHome home;
    TempWorkDir work;

    const fs::path keyfile = work.dir / "key.json";
    REQUIRE(run_cli({"keygen", keyfile.string()}).exit_code == 0);
    const std::string public_key =
        json::parse(util::slurp_text(keyfile)).at("publicKey");
    const crypto::KeyPair key = crypto::read_keyfile(keyfile);

    const fs::path pkg1 = pack_via_cli(work.dir, keyfile, public_key, "1.0.0");
    REQUIRE(run_cli({"install", pkg1.string(), "--yes"}).exit_code == 0);

    const fs::path pkg2 = pack_via_cli(work.dir, keyfile, public_key, "2.0.0");

    // update.json signed by a DIFFERENT key: the pinned installed key is the
    // trust anchor (FORMAT-0.1 §7.1) — the update must be refused.
    const crypto::KeyPair attacker = test::make_keypair();
    write_update_manifest(work.dir, attacker, "2.0.0", pkg2);
    const std::string url = to_file_url(work.dir / "update.json");
    REQUIRE(run_cli({"source", "set", kId, url}).exit_code == 0);
    CHECK(run_cli({"update", kId}).exit_code == 3);
    CHECK(*current_on_disk(kId) == "1.0.0"); // untouched

    // Properly signed update.json, but the advertised package is tampered
    // after signing: hash check (§7.4) fails, nothing is installed.
    write_update_manifest(work.dir, key, "2.0.0", pkg2);
    test::tamper_entry(pkg2, "payload/share/version.txt",
                       [](std::vector<std::uint8_t>& bytes) {
                           bytes.at(0) ^= 0xFF;
                       });
    CHECK(run_cli({"update", kId}).exit_code == 3);
    CHECK(*current_on_disk(kId) == "1.0.0");
    CHECK_FALSE(fs::exists(app_dir_on_disk(kId) / "versions" / "2.0.0"));

    const json rec = record_on_disk(kId);
    CHECK(rec.at("version") == "1.0.0");
    CHECK(rec.at("publisherKey") == public_key);
}

} // TEST_SUITE("cli_e2e")

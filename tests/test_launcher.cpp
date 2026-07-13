// launcher module tests (ARCHITECTURE.md #Tests: "launcher (runs a trivial
// payload, propagates exit code)"), plus lastRun recording, argument
// forwarding, cwd, missing-app NotFoundError, and rejection of every
// entrypoint resolution that escapes the current version directory
// (security invariant #6). Every test case constructs
// lexe::test::TempLexeHome first — no test touches the real user profile.
//
// The tests install a fake app directly through the registry (version dir +
// manifest.json copy + current pointer + installation.json) so they do not
// depend on the installer module. The payload is a trivial per-platform
// script: a .cmd on Windows, a /bin/sh script on POSIX.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/launcher.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Structurally valid but unverifiable publisher key (32 zero bytes, §4) —
// the launcher never verifies signatures, only the installer does.
constexpr const char* kZeroKey =
    "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Everything needed to fake an installed app for the launcher.
struct FakeApp {
    std::string id = "com.example.launchme";
    std::string version = "1.0.0";
#ifdef _WIN32
    std::string entrypoint = "bin/app.cmd";
#else
    std::string entrypoint = "bin/app.sh";
#endif
    std::vector<std::string> manifest_args; // entrypoint.arguments
    std::string script;                     // entrypoint file content
    bool write_entrypoint = true;  // false: manifest points at nothing
    bool exec_bit = true;          // POSIX: chmod +x the entrypoint
    /// When non-empty, written verbatim as entrypoint.executable in the
    /// manifest.json copy (may deliberately violate FORMAT-0.1 §5).
    std::string manifest_entrypoint_override;
};

/// Payload that prints a line and exits with `code`.
std::string exit_script(int code) {
#ifdef _WIN32
    return "@echo off\r\necho payload ran\r\nexit /b " + std::to_string(code) +
           "\r\n";
#else
    return "#!/bin/sh\necho payload ran\nexit " + std::to_string(code) + "\n";
#endif
}

/// Payload that writes its arguments to `args.txt` in the CWD (proving both
/// argument forwarding and cwd = version dir), then exits with `code`.
std::string args_script(int code) {
#ifdef _WIN32
    return "@echo off\r\necho %*> args.txt\r\nexit /b " + std::to_string(code) +
           "\r\n";
#else
    return "#!/bin/sh\nprintf '%s' \"$*\" > args.txt\nexit " +
           std::to_string(code) + "\n";
#endif
}

/// Payload that drops a marker file next to itself — used to prove that an
/// escaping entrypoint was never executed.
std::string marker_script() {
#ifdef _WIN32
    return "@echo off\r\necho pwned> \"%~dp0evil-ran.txt\"\r\nexit /b 0\r\n";
#else
    return "#!/bin/sh\ntouch \"$(dirname \"$0\")/evil-ran.txt\"\nexit 0\n";
#endif
}

/// Write a script file; on POSIX make it executable when `exec_bit`.
void write_script(const fs::path& file, const std::string& content,
                  bool exec_bit = true) {
    lexe::util::spit(file, std::string_view(content));
#ifdef _WIN32
    (void)exec_bit;
#else
    fs::permissions(file,
                    exec_bit ? (fs::perms::owner_all | fs::perms::group_read |
                                fs::perms::group_exec | fs::perms::others_read |
                                fs::perms::others_exec)
                             : (fs::perms::owner_read | fs::perms::owner_write),
                    fs::perm_options::replace);
#endif
}

/// Fake an installed app: version dir with the payload script, manifest.json
/// copy, `current` pointer (deterministic current.txt on every host) and
/// installation.json. Returns the version directory.
fs::path install_fake_app(const lexe::Paths& paths, const FakeApp& app) {
    lexe::Registry registry(paths);
    registry.set_use_symlinks(false); // deterministic on hosts w/o symlinks
    const fs::path version_dir = registry.version_dir(app.id, app.version);

    if (app.write_entrypoint) {
        write_script(version_dir / fs::path(app.entrypoint), app.script,
                     app.exec_bit);
    } else {
        fs::create_directories(version_dir);
    }

    const std::string manifest_entry = app.manifest_entrypoint_override.empty()
                                           ? app.entrypoint
                                           : app.manifest_entrypoint_override;
    const nlohmann::json manifest = {
        {"lexeVersion", "0.1"},
        {"id", app.id},
        {"name", "Launch Me"},
        {"version", app.version},
        {"publisher", {{"name", "Test Publisher"}, {"publicKey", kZeroKey}}},
        {"applicationType", "native"},
        {"architectures", nlohmann::json::array({"x86_64", "aarch64"})},
        {"entrypoint",
         {{"executable", manifest_entry}, {"arguments", app.manifest_args}}},
        {"install", {{"scope", "user"}, {"mode", "bundled"}}},
    };
    const std::string text = manifest.dump(2) + "\n";
    registry.write_manifest_bytes(
        app.id, std::vector<std::uint8_t>(text.begin(), text.end()));

    registry.set_current_version(app.id, app.version);

    lexe::InstallationRecord record;
    record.id = app.id;
    record.version = app.version;
    record.source = "test://fake-install";
    record.publisher_key = kZeroKey;
    record.installed_at = lexe::util::now_utc_string();
    registry.write_record(record);

    return version_dir;
}

std::string trimmed(std::string text) {
    const char* ws = " \t\r\n";
    const std::size_t first = text.find_first_not_of(ws);
    if (first == std::string::npos) return {};
    const std::size_t last = text.find_last_not_of(ws);
    return text.substr(first, last - first + 1);
}

/// Loose RFC 3339 UTC shape check: "YYYY-MM-DDThh:mm:ssZ".
bool looks_like_rfc3339_utc(const std::string& s) {
    if (s.size() != 20) return false;
    return s[4] == '-' && s[7] == '-' && s[10] == 'T' && s[13] == ':' &&
           s[16] == ':' && s[19] == 'Z';
}

/// Can this process create directory symlinks here? (On Windows this needs
/// Developer Mode or admin rights; the symlink-escape test skips gracefully
/// when unavailable.)
bool symlinks_supported(const fs::path& scratch) {
    std::error_code ec;
    fs::create_directories(scratch / "slt-target", ec);
    if (ec) return false;
    fs::create_directory_symlink(scratch / "slt-target", scratch / "slt-link",
                                 ec);
    const bool ok = !ec && fs::is_symlink(scratch / "slt-link");
    std::error_code cleanup;
    fs::remove(scratch / "slt-link", cleanup);
    fs::remove(scratch / "slt-target", cleanup);
    return ok;
}

} // namespace

TEST_SUITE("launcher") {

TEST_CASE("runs a trivial payload and returns its zero exit code") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    FakeApp app;
    app.script = exit_script(0);
    install_fake_app(paths, app);

    CHECK(lexe::run_app(paths, app.id, {}) == 0);
}

TEST_CASE("propagates nonzero exit codes verbatim") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    FakeApp app7;
    app7.id = "com.example.exit-seven";
    app7.script = exit_script(7);
    install_fake_app(paths, app7);
    CHECK(lexe::run_app(paths, app7.id, {}) == 7);

    FakeApp app42;
    app42.id = "com.example.exit-fortytwo";
    app42.script = exit_script(42);
    install_fake_app(paths, app42);
    CHECK(lexe::run_app(paths, app42.id, {}) == 42);
}

TEST_CASE("records lastRun timestamp and exit code in installation.json") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    const lexe::Registry registry(paths);

    FakeApp app;
    app.script = exit_script(7);
    const fs::path version_dir = install_fake_app(paths, app);

    // Never run yet: lastRun is empty.
    CHECK(registry.read_record(app.id).last_run_at.empty());

    CHECK(lexe::run_app(paths, app.id, {}) == 7);
    lexe::InstallationRecord record = registry.read_record(app.id);
    CHECK(record.last_exit_code == 7);
    CHECK(looks_like_rfc3339_utc(record.last_run_at));

    // A later run overwrites lastRun with the new outcome.
    write_script(version_dir / fs::path(app.entrypoint), exit_script(0));
    CHECK(lexe::run_app(paths, app.id, {}) == 0);
    record = registry.read_record(app.id);
    CHECK(record.last_exit_code == 0);
    CHECK(looks_like_rfc3339_utc(record.last_run_at));

    // The rest of the record survives the rewrite untouched.
    CHECK(record.id == app.id);
    CHECK(record.version == app.version);
    CHECK(record.source == "test://fake-install");
    CHECK(record.publisher_key == std::string(kZeroKey));
}

TEST_CASE("appends caller args after manifest arguments, cwd = version dir") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    FakeApp app;
    app.manifest_args = {"--from-manifest"};
    app.script = args_script(5);
    const fs::path version_dir = install_fake_app(paths, app);

    CHECK(lexe::run_app(paths, app.id, {"alpha", "bravo"}) == 5);

    // args.txt lands in the child's CWD — its presence in the version dir
    // proves the launcher spawned with cwd = version dir.
    const fs::path args_file = version_dir / "args.txt";
    REQUIRE(fs::is_regular_file(args_file));
    CHECK(trimmed(lexe::util::slurp_text(args_file)) ==
          "--from-manifest alpha bravo");
}

TEST_CASE("missing app -> NotFoundError") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    CHECK_THROWS_AS(lexe::run_app(paths, "com.example.absent", {}),
                    lexe::NotFoundError);

    // An app directory without installation.json is not installed either.
    fs::create_directories(paths.apps_dir() / "com.example.hollow" /
                           "versions" / "1.0.0");
    CHECK_THROWS_AS(lexe::run_app(paths, "com.example.hollow", {}),
                    lexe::NotFoundError);

    // A malformed id never reaches the filesystem join (registry rejects it).
    CHECK_THROWS_AS(lexe::run_app(paths, "not-reverse-dns", {}), lexe::Error);
}

TEST_CASE("installed app without a current version -> NotFoundError") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    FakeApp app;
    app.script = exit_script(0);
    install_fake_app(paths, app);
    fs::remove(paths.apps_dir() / app.id / "current.txt");

    CHECK_THROWS_AS(lexe::run_app(paths, app.id, {}), lexe::NotFoundError);
}

TEST_CASE("missing entrypoint file -> Error") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    FakeApp app;
    app.write_entrypoint = false; // manifest points at nothing
    install_fake_app(paths, app);

    CHECK_THROWS_AS(lexe::run_app(paths, app.id, {}), lexe::Error);
}

TEST_CASE("entrypoint that is a directory -> Error") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    FakeApp app;
    app.write_entrypoint = false;
    const fs::path version_dir = install_fake_app(paths, app);
    fs::create_directories(version_dir / fs::path(app.entrypoint));

    CHECK_THROWS_AS(lexe::run_app(paths, app.id, {}), lexe::Error);
}

TEST_CASE("traversal/absolute/drive entrypoints in the manifest copy are "
          "rejected and never executed") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    // Plant a marker-dropping script three levels above the version dir
    // (<apps>/evil.*) — exactly where "../../../…" would land.
    const std::string evil_name =
#ifdef _WIN32
        "evil.cmd";
#else
        "evil.sh";
#endif
    write_script(paths.apps_dir() / evil_name, marker_script());

    const std::vector<std::string> hostile_entrypoints = {
        "../../../" + evil_name,       // ".." segments
        "/" + evil_name,               // absolute POSIX path
        "C:/Windows/System32/cmd.exe", // Windows drive designator
        "bin\\app.cmd",                // backslash
    };
    int n = 0;
    for (const std::string& hostile : hostile_entrypoints) {
        CAPTURE(hostile);
        FakeApp app;
        app.id = "com.example.hostile" + std::to_string(n++);
        app.script = exit_script(0);
        app.manifest_entrypoint_override = hostile;
        install_fake_app(paths, app);

        CHECK_THROWS_AS(lexe::run_app(paths, app.id, {}), lexe::Error);
    }
    CHECK_FALSE(fs::exists(paths.apps_dir() / "evil-ran.txt"));
}

TEST_CASE("containment check rejects an entrypoint resolving to the version "
          "dir itself") {
    // "." passes every FORMAT-0.1 §5 lexical rule, so it reaches the
    // launcher's own canonical-containment check — the entrypoint must be a
    // file strictly inside the version directory (invariant #6). This
    // exercises the rejection branch on hosts without symlink support too.
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    FakeApp app;
    app.script = exit_script(0);
    app.manifest_entrypoint_override = ".";
    install_fake_app(paths, app);

    try {
        lexe::run_app(paths, app.id, {});
        FAIL("expected lexe::Error");
    } catch (const lexe::Error& e) {
        CHECK(std::string(e.what()).find(
                  "resolves outside the current version directory") !=
              std::string::npos);
    }
}

TEST_CASE("entrypoint escaping through a symlinked subdirectory is rejected") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    if (!symlinks_supported(home.path())) {
        MESSAGE("symlinks unavailable on this host; skipping symlink-escape "
                "check (exercised on Linux CI)");
        return;
    }

    // A marker-dropping script OUTSIDE the app dir…
    const std::string evil_name =
#ifdef _WIN32
        "evil.cmd";
#else
        "evil.sh";
#endif
    const fs::path outside = home.path() / "outside";
    write_script(outside / evil_name, marker_script());

    // …reached via a §5-clean relative entrypoint through a symlink.
    FakeApp app;
    app.write_entrypoint = false;
    app.entrypoint = "escape/" + evil_name; // passes Manifest::parse
    const fs::path version_dir = install_fake_app(paths, app);
    fs::create_directory_symlink(outside, version_dir / "escape");
    REQUIRE(fs::is_regular_file(version_dir / "escape" / evil_name));

    CHECK_THROWS_AS(lexe::run_app(paths, app.id, {}), lexe::Error);
    CHECK_FALSE(fs::exists(outside / "evil-ran.txt")); // never executed
}

TEST_CASE("tampered current pointer cannot traverse out of versions/") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    // A runnable script parked outside versions/ that a traversing current
    // pointer would otherwise reach.
    FakeApp app;
    app.script = exit_script(0);
    install_fake_app(paths, app);
    lexe::util::spit(paths.apps_dir() / app.id / "current.txt",
                     std::string_view("../../evil\n"));

    CHECK_THROWS_AS(lexe::run_app(paths, app.id, {}), lexe::Error);
}

#ifndef _WIN32
TEST_CASE("POSIX: missing exec bit is set before launch") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    FakeApp app;
    app.script = exit_script(0);
    app.exec_bit = false; // simulate extraction that dropped mode bits
    const fs::path version_dir = install_fake_app(paths, app);
    const fs::path entry = version_dir / fs::path(app.entrypoint);
    REQUIRE((fs::status(entry).permissions() & fs::perms::owner_exec) ==
            fs::perms::none);

    CHECK(lexe::run_app(paths, app.id, {}) == 0);
    CHECK((fs::status(entry).permissions() & fs::perms::owner_exec) !=
          fs::perms::none);
}
#endif

TEST_CASE("launches the shared test-app payload (helpers tree)") {
    // The tree make_test_app_tree/make_test_package produce (per-platform
    // entrypoint: bin/hello.cmd on Windows, bin/hello.sh on POSIX) must be
    // launchable — installer/updater/e2e tests all rely on this payload.
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    const lexe::test::TestAppTree tree = lexe::test::make_test_app_tree(
        home.path() / "tree", lexe::test::TestAppSpec{});

    lexe::Registry registry(paths);
    registry.set_use_symlinks(false);
    const fs::path version_dir =
        registry.version_dir(tree.spec.id, tree.spec.version);
    lexe::util::copy_recursive(tree.payload_dir, version_dir);
    registry.write_manifest_bytes(tree.spec.id,
                                  lexe::util::slurp(tree.manifest_file));
    registry.set_current_version(tree.spec.id, tree.spec.version);
    lexe::InstallationRecord record;
    record.id = tree.spec.id;
    record.version = tree.spec.version;
    record.source = tree.root.string();
    record.publisher_key = tree.spec.public_key;
    record.installed_at = lexe::util::now_utc_string();
    registry.write_record(record);

    CHECK(lexe::run_app(paths, tree.spec.id, {}) == 0);
    CHECK(registry.read_record(tree.spec.id).last_exit_code == 0);
}

} // TEST_SUITE("launcher")

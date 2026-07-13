// registry module tests (ARCHITECTURE.md #Tests: "registry round-trip +
// current-link fallback"). Every test case constructs lexe::test::TempLexeHome
// first so LEXE_HOME points into a fresh temp directory.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// Can this process create directory symlinks here? (On Windows this needs
/// Developer Mode or admin rights; tests skip the symlink path gracefully
/// when it is unavailable, per FORMAT-0.1 §9.)
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

/// A fully populated record for round-trip tests.
lexe::InstallationRecord full_record() {
    lexe::InstallationRecord r;
    r.id = "com.example.hello";
    r.version = "1.4.2";
    r.source = "C:/downloads/Hello-1.4.2.lexe";
    r.publisher_key = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    r.channel = "beta";
    r.update_url = "https://example.com/releases/update.json";
    r.installed_at = "2026-07-13T08:00:00Z";
    r.last_run_at = "2026-07-13T09:30:00Z";
    r.last_exit_code = 3;
    r.created_files = {"/tmp/xdg/applications/lexe-com.example.hello.desktop",
                       "/tmp/xdg/icons/hicolor/128x128/apps/com.example.hello.png"};
    return r;
}

} // namespace

TEST_SUITE("registry") {

TEST_CASE("InstallationRecord JSON round-trips every field") {
    lexe::test::TempLexeHome home;

    const lexe::InstallationRecord r = full_record();
    const std::string text = r.to_json();
    const lexe::InstallationRecord back =
        lexe::InstallationRecord::from_json(text);

    CHECK(back.id == r.id);
    CHECK(back.version == r.version);
    CHECK(back.source == r.source);
    CHECK(back.publisher_key == r.publisher_key);
    CHECK(back.channel == r.channel);
    CHECK(back.update_url == r.update_url);
    CHECK(back.installed_at == r.installed_at);
    CHECK(back.last_run_at == r.last_run_at);
    CHECK(back.last_exit_code == r.last_exit_code);
    CHECK(back.created_files == r.created_files);

    // The serialized form uses the documented field names (FORMAT-0.1 §9).
    const auto j = nlohmann::json::parse(text);
    for (const char* key : {"id", "version", "source", "publisherKey",
                            "channel", "updateUrl", "installedAtUtc",
                            "lastRun", "createdFiles"}) {
        CAPTURE(key);
        CHECK(j.contains(key));
    }
    CHECK(j["lastRun"]["at"] == r.last_run_at);
    CHECK(j["lastRun"]["exitCode"] == r.last_exit_code);
}

TEST_CASE("InstallationRecord defaults: minimal JSON and never-run lastRun") {
    lexe::test::TempLexeHome home;

    const lexe::InstallationRecord r =
        lexe::InstallationRecord::from_json(R"({"id":"com.example.min"})");
    CHECK(r.id == "com.example.min");
    CHECK(r.version.empty());
    CHECK(r.source.empty());
    CHECK(r.publisher_key.empty());
    CHECK(r.channel == "stable"); // default channel (§7.3)
    CHECK(r.update_url.empty());
    CHECK(r.installed_at.empty());
    CHECK(r.last_run_at.empty());
    CHECK(r.last_exit_code == 0);
    CHECK(r.created_files.empty());

    // An app that never ran serializes lastRun as null and parses back.
    lexe::InstallationRecord fresh;
    fresh.id = "com.example.min";
    const auto j = nlohmann::json::parse(fresh.to_json());
    CHECK(j["lastRun"].is_null());
    const lexe::InstallationRecord back =
        lexe::InstallationRecord::from_json(fresh.to_json());
    CHECK(back.last_run_at.empty());
    CHECK(back.last_exit_code == 0);
}

TEST_CASE("InstallationRecord rejects malformed contents") {
    lexe::test::TempLexeHome home;

    const char* bad[] = {
        "not json at all",
        "[]",                                        // wrong top-level type
        "{}",                                        // missing id
        R"({"id":""})",                              // empty id
        R"({"id":42})",                              // id wrong type
        R"({"id":"com.example.a","channel":7})",     // channel wrong type
        R"({"id":"com.example.a","createdFiles":"x"})",
        R"({"id":"com.example.a","createdFiles":[1]})",
        R"({"id":"com.example.a","lastRun":"yes"})",
        R"({"id":"com.example.a","lastRun":{"exitCode":"zero"}})",
    };
    for (const char* text : bad) {
        CAPTURE(text);
        CHECK_THROWS_AS(lexe::InstallationRecord::from_json(text), lexe::Error);
    }
}

TEST_CASE("write_record / read_record round-trip on disk") {
    lexe::test::TempLexeHome home;
    const lexe::Registry reg(lexe::Paths::detect());

    const lexe::InstallationRecord r = full_record();
    CHECK_FALSE(reg.is_installed(r.id));

    reg.write_record(r);
    CHECK(reg.is_installed(r.id));
    CHECK(fs::is_regular_file(home.path() / "apps" / r.id /
                              "installation.json"));

    const lexe::InstallationRecord back = reg.read_record(r.id);
    CHECK(back.id == r.id);
    CHECK(back.version == r.version);
    CHECK(back.source == r.source);
    CHECK(back.publisher_key == r.publisher_key);
    CHECK(back.channel == r.channel);
    CHECK(back.update_url == r.update_url);
    CHECK(back.installed_at == r.installed_at);
    CHECK(back.last_run_at == r.last_run_at);
    CHECK(back.last_exit_code == r.last_exit_code);
    CHECK(back.created_files == r.created_files);
}

TEST_CASE("record created files: appended paths persist across re-reads") {
    lexe::test::TempLexeHome home;
    const lexe::Registry reg(lexe::Paths::detect());

    lexe::InstallationRecord r;
    r.id = "com.example.files";
    r.version = "1.0.0";
    r.installed_at = lexe::util::now_utc_string();
    reg.write_record(r);

    // The installer/desktop flow: read, record a created file, write back.
    lexe::InstallationRecord step1 = reg.read_record(r.id);
    step1.created_files.push_back("/xdg/applications/lexe-com.example.files.desktop");
    reg.write_record(step1);

    lexe::InstallationRecord step2 = reg.read_record(r.id);
    step2.created_files.push_back("/xdg/mime/packages/com.example.files.xml");
    reg.write_record(step2);

    const lexe::InstallationRecord final_state = reg.read_record(r.id);
    REQUIRE(final_state.created_files.size() == 2);
    CHECK(final_state.created_files[0] ==
          "/xdg/applications/lexe-com.example.files.desktop");
    CHECK(final_state.created_files[1] ==
          "/xdg/mime/packages/com.example.files.xml");
}

TEST_CASE("missing id: read_record / current_version / read_manifest throw NotFoundError") {
    lexe::test::TempLexeHome home;
    const lexe::Registry reg(lexe::Paths::detect());

    CHECK_FALSE(reg.is_installed("com.example.absent"));
    CHECK_THROWS_AS((void)reg.read_record("com.example.absent"),
                    lexe::NotFoundError);
    CHECK_THROWS_AS((void)reg.current_version("com.example.absent"),
                    lexe::NotFoundError);
    CHECK_THROWS_AS((void)reg.read_manifest("com.example.absent"),
                    lexe::NotFoundError);

    // Installed app without a current pointer is also NotFoundError.
    lexe::InstallationRecord r;
    r.id = "com.example.nocurrent";
    reg.write_record(r);
    CHECK_THROWS_AS((void)reg.current_version("com.example.nocurrent"),
                    lexe::NotFoundError);
}

TEST_CASE("list_installed across multiple ids, ignoring strays") {
    lexe::test::TempLexeHome home;
    const lexe::Registry reg(lexe::Paths::detect());

    CHECK(reg.list_installed().empty()); // apps/ does not even exist yet

    for (const char* id : {"org.zeta.tool", "com.example.hello",
                           "io.middle.app"}) {
        lexe::InstallationRecord r;
        r.id = id;
        r.version = "1.0.0";
        reg.write_record(r);
    }
    // Strays that must NOT be listed: a directory without installation.json
    // and a plain file directly under apps/.
    fs::create_directories(home.path() / "apps" / "com.example.leftover");
    lexe::util::spit(home.path() / "apps" / "stray.txt",
                     std::string_view("not an app\n"));

    const std::vector<std::string> ids = reg.list_installed();
    const std::vector<std::string> expected = {
        "com.example.hello", "io.middle.app", "org.zeta.tool"}; // sorted
    CHECK(ids == expected);
    CHECK(reg.is_installed("com.example.hello"));
    CHECK_FALSE(reg.is_installed("com.example.leftover"));
}

TEST_CASE("set/resolve current via the current.txt fallback (forced)") {
    lexe::test::TempLexeHome home;
    lexe::Registry reg(lexe::Paths::detect());
    reg.set_use_symlinks(false); // force the text fallback deterministically

    const std::string id = "com.example.fallback";
    fs::create_directories(reg.version_dir(id, "1.0.0"));
    fs::create_directories(reg.version_dir(id, "1.1.0"));

    reg.set_current_version(id, "1.0.0");
    const fs::path txt = reg.app_dir(id) / "current.txt";
    CHECK(fs::is_regular_file(txt));
    CHECK_FALSE(fs::exists(fs::symlink_status(reg.app_dir(id) / "current")));
    CHECK(reg.current_version(id) == "1.0.0");

    // Flip to another version: the fallback file is rewritten.
    reg.set_current_version(id, "1.1.0");
    CHECK(reg.current_version(id) == "1.1.0");
    CHECK(lexe::util::slurp_text(txt) == "1.1.0\n");

    // Missing version directory -> NotFoundError, current unchanged.
    CHECK_THROWS_AS(reg.set_current_version(id, "9.9.9"),
                    lexe::NotFoundError);
    CHECK(reg.current_version(id) == "1.1.0");
}

TEST_CASE("current_version reads a hand-written current.txt, trimming whitespace") {
    lexe::test::TempLexeHome home;
    const lexe::Registry reg(lexe::Paths::detect());

    const std::string id = "com.example.textfile";
    fs::create_directories(reg.version_dir(id, "2.0.1"));
    lexe::util::spit(reg.app_dir(id) / "current.txt",
                     std::string_view("2.0.1\r\n"));
    CHECK(reg.current_version(id) == "2.0.1");

    // A whitespace-only current.txt does not resolve.
    lexe::util::spit(reg.app_dir(id) / "current.txt", std::string_view("\r\n"));
    CHECK_THROWS_AS((void)reg.current_version(id), lexe::NotFoundError);
}

TEST_CASE("set/resolve current via symlink when the platform allows") {
    lexe::test::TempLexeHome home;
    lexe::Registry reg(lexe::Paths::detect());

    const std::string id = "com.example.symlink";
    fs::create_directories(reg.version_dir(id, "1.0.0"));
    fs::create_directories(reg.version_dir(id, "2.0.0"));
    const fs::path link = reg.app_dir(id) / "current";
    const fs::path txt = reg.app_dir(id) / "current.txt";

    if (!symlinks_supported(home.path())) {
        // Graceful skip of the symlink assertions: verify the automatic
        // fallback engages instead (the whole point of current.txt).
        MESSAGE("symlinks unavailable on this host; "
                "verifying automatic fallback instead");
        reg.set_current_version(id, "1.0.0");
        CHECK_FALSE(fs::is_symlink(link));
        CHECK(fs::is_regular_file(txt));
        CHECK(reg.current_version(id) == "1.0.0");
        return;
    }

    // Seed a stale text fallback; a successful symlink set must remove it.
    reg.set_use_symlinks(false);
    reg.set_current_version(id, "2.0.0");
    CHECK(fs::is_regular_file(txt));

    reg.set_use_symlinks(true);
    reg.set_current_version(id, "1.0.0");
    CHECK(fs::is_symlink(link));
    CHECK_FALSE(fs::exists(txt));
    CHECK(reg.current_version(id) == "1.0.0");
    // The link target is relative (survives a moved LEXE_HOME) and resolves
    // to the version directory.
    CHECK(fs::read_symlink(link).is_relative());
    CHECK(fs::equivalent(link, reg.version_dir(id, "1.0.0")));

    // Flip current to another version through the symlink path.
    reg.set_current_version(id, "2.0.0");
    CHECK(fs::is_symlink(link));
    CHECK(reg.current_version(id) == "2.0.0");
    CHECK(fs::equivalent(link, reg.version_dir(id, "2.0.0")));

    // When both mechanisms are somehow present, the symlink wins.
    lexe::util::spit(txt, std::string_view("1.0.0\n"));
    CHECK(reg.current_version(id) == "2.0.0");
}

TEST_CASE("installed_versions lists version directories, unordered") {
    lexe::test::TempLexeHome home;
    const lexe::Registry reg(lexe::Paths::detect());

    const std::string id = "com.example.versions";
    CHECK(reg.installed_versions(id).empty()); // nothing installed

    for (const char* v : {"1.0.0", "1.10.0", "2.0.0-beta"}) {
        fs::create_directories(reg.version_dir(id, v));
    }
    // A stray file under versions/ is not a version.
    lexe::util::spit(reg.app_dir(id) / "versions" / "notes.txt",
                     std::string_view("stray\n"));

    std::vector<std::string> versions = reg.installed_versions(id);
    std::sort(versions.begin(), versions.end());
    const std::vector<std::string> expected = {"1.0.0", "1.10.0", "2.0.0-beta"};
    CHECK(versions == expected);
}

TEST_CASE("manifest.json copy: exact bytes stored, read_manifest parses them") {
    lexe::test::TempLexeHome home;
    const lexe::Registry reg(lexe::Paths::detect());

    lexe::test::TestAppSpec spec;
    spec.id = "com.example.manifested";
    spec.version = "3.1.4";
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(home.path() / "scratch-tree", spec);
    const std::vector<std::uint8_t> bytes =
        lexe::util::slurp(tree.manifest_file);

    reg.write_manifest_bytes(spec.id, bytes);
    // Stored verbatim (the runtime copies the exact lexe.json bytes, §9)…
    CHECK(lexe::util::slurp(reg.app_dir(spec.id) / "manifest.json") == bytes);
    // …and parses back through Manifest::parse.
    const lexe::Manifest m = reg.read_manifest(spec.id);
    CHECK(m.id == spec.id);
    CHECK(m.version == spec.version);
    CHECK(m.lexe_version == "0.1");
    CHECK(m.publisher_public_key == spec.public_key);
}

TEST_CASE("hostile ids and versions never become paths") {
    lexe::test::TempLexeHome home;
    const lexe::Registry reg(lexe::Paths::detect());

    const char* bad_ids[] = {
        "",             // empty
        "nodots",       // fewer than 2 segments
        "com..empty",   // empty segment
        ".com.example", // leading empty segment
        "com.example.", // trailing empty segment
        "../evil.app",  // traversal
        "com.example/payload", // path separator
        "com.example\\payload", // backslash
        "com.exa mple", // disallowed character
    };
    for (const char* id : bad_ids) {
        CAPTURE(id);
        CHECK_THROWS_AS((void)reg.app_dir(id), lexe::Error);
        CHECK_THROWS_AS((void)reg.read_record(id), lexe::Error);
        CHECK_THROWS_AS((void)reg.is_installed(id), lexe::Error);
    }

    const std::string good_id = "com.example.safe";
    fs::create_directories(reg.app_dir(good_id) / "versions");
    const char* bad_versions[] = {"", ".", "..", "1.0/..", "a\\b", "C:evil"};
    for (const char* v : bad_versions) {
        CAPTURE(v);
        CHECK_THROWS_AS((void)reg.version_dir(good_id, v), lexe::Error);
        CHECK_THROWS_AS(reg.set_current_version(good_id, v), lexe::Error);
    }

    // A record whose id is hostile is refused before any path is formed.
    lexe::InstallationRecord r;
    r.id = "../evil.app";
    CHECK_THROWS_AS(reg.write_record(r), lexe::Error);
    CHECK_FALSE(fs::exists(home.path().parent_path() / "evil.app"));
}

} // TEST_SUITE("registry")

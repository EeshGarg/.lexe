// desktop module tests (ARCHITECTURE.md #Tests) — pure content generation
// (desktop entries, MIME XML, escaping) verified on every platform;
// would-create lists asserted exactly against the fixture manifest under a
// temp LEXE_HOME-derived XDG layout (this is what the Windows dev host
// checks); actual file creation/removal verified on Linux.
// Every test case constructs lexe::test::TempLexeHome first — no test
// touches the real user profile.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/desktop.hpp"
#include "core/manifest.hpp"
#include "core/paths.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// The fixture manifest all planning tests use (a valid FORMAT-0.1 §5
/// manifest with integration extras).
lexe::Manifest fixture_manifest() {
    lexe::Manifest m;
    m.lexe_version = "0.1";
    m.id = "com.example.hello";
    m.name = "Hello App";
    m.version = "1.4.2";
    m.publisher_name = "Test Publisher";
    m.publisher_public_key =
        "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    m.application_type = "native";
    m.architectures = {"x86_64"};
    m.entrypoint_executable = "bin/hello.sh";
    m.install_mode = "bundled";
    m.categories = {"Utility", "Development"};
    m.file_associations = {{".example", "application/x-example"}};
    return m;
}

/// Create a package-shaped icons/ source dir with all four FORMAT-0.1 §2
/// icon entries, each with distinct bytes.
fs::path make_icons_dir(const fs::path& dir) {
    lexe::util::spit(dir / "64.png", std::string_view("png-64-bytes"));
    lexe::util::spit(dir / "128.png", std::string_view("png-128-bytes"));
    lexe::util::spit(dir / "256.png", std::string_view("png-256-bytes"));
    lexe::util::spit(dir / "scalable.svg", std::string_view("<svg/>"));
    return dir;
}

std::size_t count_occurrences(const std::string& text,
                              const std::string& needle) {
    std::size_t n = 0;
    for (std::size_t pos = text.find(needle); pos != std::string::npos;
         pos = text.find(needle, pos + needle.size())) {
        ++n;
    }
    return n;
}

void check_lists_equal(const std::vector<std::string>& actual,
                       const std::vector<std::string>& expected) {
    REQUIRE_EQ(actual.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        CAPTURE(i);
        CHECK_EQ(actual[i], expected[i]);
    }
}

} // namespace

TEST_SUITE("desktop") {

// ---------------------------------------------------------------------------
// Content generation — pure string output, verified on every platform.
// ---------------------------------------------------------------------------

TEST_CASE("desktop entry text: exact content for the fixture manifest") {
    lexe::test::TempLexeHome home;
    const lexe::Manifest m = fixture_manifest();

    const std::string text = lexe::desktop::desktop_entry_text(m);
    const std::string expected =
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Hello App\n"
        "Exec=lexe run com.example.hello\n"
        "Icon=lexe-com.example.hello\n"
        "Terminal=false\n"
        "Categories=Utility;Development;\n"
        "MimeType=application/x-example;\n"
        "X-Lexe-Id=com.example.hello\n";
    CHECK_EQ(text, expected);
}

TEST_CASE("desktop entry Exec is the stable launcher, never a versioned path") {
    lexe::test::TempLexeHome home;
    const lexe::Manifest m = fixture_manifest(); // version 1.4.2

    const std::string text = lexe::desktop::desktop_entry_text(m);
    CHECK(text.find("Exec=lexe run com.example.hello\n") != std::string::npos);
    // SPEC "Installed Application Representation": no version-specific path.
    CHECK_EQ(text.find("1.4.2"), std::string::npos);
    CHECK_EQ(text.find("versions"), std::string::npos);
    CHECK_EQ(text.find("bin/hello.sh"), std::string::npos);
}

TEST_CASE("desktop entry text: Categories and MimeType omitted when empty") {
    lexe::test::TempLexeHome home;
    lexe::Manifest m = fixture_manifest();
    m.categories.clear();
    m.file_associations.clear();

    const std::string text = lexe::desktop::desktop_entry_text(m);
    CHECK_EQ(text.find("Categories="), std::string::npos);
    CHECK_EQ(text.find("MimeType="), std::string::npos);
    CHECK(text.find("Name=Hello App\n") != std::string::npos);
    CHECK(text.find("Exec=lexe run com.example.hello\n") != std::string::npos);
}

TEST_CASE("desktop entry text: duplicate mime types are deduplicated") {
    lexe::test::TempLexeHome home;
    lexe::Manifest m = fixture_manifest();
    m.file_associations = {{".example", "application/x-example"},
                           {".exm", "application/x-example"},
                           {".foo", "application/x-foo"}};

    const std::string text = lexe::desktop::desktop_entry_text(m);
    CHECK(text.find("MimeType=application/x-example;application/x-foo;\n") !=
          std::string::npos);
    CHECK_EQ(count_occurrences(text, "application/x-example"), 1u);
}

TEST_CASE("desktop entry text: values are Desktop-Entry escaped") {
    lexe::test::TempLexeHome home;
    lexe::Manifest m = fixture_manifest();
    m.name = "Line1\nTab\tBack\\slash\rEnd";
    m.categories = {"Weird;Cat"};

    const std::string text = lexe::desktop::desktop_entry_text(m);
    // Literal backslash escape sequences, no raw control characters.
    CHECK(text.find("Name=Line1\\nTab\\tBack\\\\slash\\rEnd\n") !=
          std::string::npos);
    CHECK(text.find("Categories=Weird\\;Cat;\n") != std::string::npos);
    CHECK_EQ(text.find("Line1\nTab"), std::string::npos);
    CHECK_EQ(text.find('\t'), std::string::npos);
    CHECK_EQ(text.find('\r'), std::string::npos);
}

TEST_CASE("mime xml text: exact document, grouped by mime type") {
    lexe::test::TempLexeHome home;
    lexe::Manifest m = fixture_manifest();
    m.file_associations = {{".example", "application/x-example"},
                           {".exm", "application/x-example"},
                           {"foo", "application/x-foo"}}; // no leading dot

    const std::string xml = lexe::desktop::mime_xml_text(m);
    const std::string expected =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<mime-info xmlns=\"http://www.freedesktop.org/standards/"
        "shared-mime-info\">\n"
        "  <mime-type type=\"application/x-example\">\n"
        "    <comment>Hello App document</comment>\n"
        "    <glob pattern=\"*.example\"/>\n"
        "    <glob pattern=\"*.exm\"/>\n"
        "  </mime-type>\n"
        "  <mime-type type=\"application/x-foo\">\n"
        "    <comment>Hello App document</comment>\n"
        "    <glob pattern=\"*.foo\"/>\n"
        "  </mime-type>\n"
        "</mime-info>\n";
    CHECK_EQ(xml, expected);
    CHECK_EQ(count_occurrences(xml, "<mime-type"), 2u);
}

TEST_CASE("mime xml text: XML-special characters are escaped") {
    lexe::test::TempLexeHome home;
    lexe::Manifest m = fixture_manifest();
    m.name = "Ann & Bob's <\"App\">";
    m.file_associations = {{".e&x", "application/x-a&b"}};

    const std::string xml = lexe::desktop::mime_xml_text(m);
    CHECK(xml.find("type=\"application/x-a&amp;b\"") != std::string::npos);
    CHECK(xml.find("pattern=\"*.e&amp;x\"") != std::string::npos);
    CHECK(xml.find("<comment>Ann &amp; Bob&apos;s &lt;&quot;App&quot;&gt; "
                   "document</comment>") != std::string::npos);
    // No raw specials outside markup: every '&' must be part of an entity.
    CHECK_EQ(count_occurrences(xml, "&"),
             count_occurrences(xml, "&amp;") + count_occurrences(xml, "&lt;") +
                 count_occurrences(xml, "&gt;") +
                 count_occurrences(xml, "&quot;") +
                 count_occurrences(xml, "&apos;"));
}

TEST_CASE("runtime desktop entry and mime xml register application/x-lexe") {
    lexe::test::TempLexeHome home;

    const std::string entry = lexe::desktop::runtime_desktop_entry_text();
    CHECK(entry.rfind("[Desktop Entry]\n", 0) == 0);
    CHECK(entry.find("Exec=lexe-installer %f\n") != std::string::npos);
    CHECK(entry.find("MimeType=application/x-lexe;\n") != std::string::npos);
    CHECK(entry.find("Name=Lexe Installer\n") != std::string::npos);
    CHECK(entry.find("Terminal=false\n") != std::string::npos);

    const std::string xml = lexe::desktop::runtime_mime_xml_text();
    CHECK(xml.find("<mime-type type=\"application/x-lexe\">") !=
          std::string::npos);
    CHECK(xml.find("<glob pattern=\"*.lexe\"/>") != std::string::npos);
    CHECK(xml.find("http://www.freedesktop.org/standards/shared-mime-info") !=
          std::string::npos);
}

// ---------------------------------------------------------------------------
// integrate_app — would-create planning (exact on all platforms; on the
// Windows dev host this is what installation.json would record).
// ---------------------------------------------------------------------------

TEST_CASE("integrate_app returns exactly the would-create list for the "
          "fixture manifest") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    const lexe::Manifest m = fixture_manifest();
    const fs::path icons = make_icons_dir(home.path() / "staging-icons");

    const auto result = lexe::desktop::integrate_app(paths, m, icons);

    const std::string base = "lexe-com.example.hello";
    const std::vector<std::string> expected = {
        (paths.applications_dir() / (base + ".desktop")).string(),
        (paths.icons_dir() / "64x64" / "apps" / (base + ".png")).string(),
        (paths.icons_dir() / "128x128" / "apps" / (base + ".png")).string(),
        (paths.icons_dir() / "256x256" / "apps" / (base + ".png")).string(),
        (paths.icons_dir() / "scalable" / "apps" / (base + ".svg")).string(),
        (paths.mime_dir() / "packages" / (base + ".xml")).string(),
    };
    check_lists_equal(result.created_files, expected);
    for (const auto& f : result.created_files) {
        CAPTURE(f);
        CHECK(fs::path(f).is_absolute());
    }

#ifdef _WIN32
    CHECK(result.status == lexe::desktop::IntegrationStatus::skipped);
    // Recorded no-op: nothing may actually be written on Windows.
    for (const auto& f : result.created_files) {
        CAPTURE(f);
        CHECK_FALSE(fs::exists(fs::path(f)));
    }
#else
    CHECK(result.status == lexe::desktop::IntegrationStatus::applied);
    for (const auto& f : result.created_files) {
        CAPTURE(f);
        CHECK(fs::exists(fs::path(f)));
    }
#endif
}

TEST_CASE("integrate_app: nonexistent icons dir means no icon files") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    const lexe::Manifest m = fixture_manifest();

    const auto result = lexe::desktop::integrate_app(
        paths, m, home.path() / "no-such-icons");

    const std::string base = "lexe-com.example.hello";
    const std::vector<std::string> expected = {
        (paths.applications_dir() / (base + ".desktop")).string(),
        (paths.mime_dir() / "packages" / (base + ".xml")).string(),
    };
    check_lists_equal(result.created_files, expected);
}

TEST_CASE("integrate_app: only the icon sizes present are planned") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    const lexe::Manifest m = fixture_manifest();
    const fs::path icons = home.path() / "staging-icons";
    lexe::util::spit(icons / "128.png", std::string_view("png-128-bytes"));
    lexe::util::spit(icons / "unrelated.txt", std::string_view("ignored"));

    const auto result = lexe::desktop::integrate_app(paths, m, icons);

    const std::string base = "lexe-com.example.hello";
    const std::vector<std::string> expected = {
        (paths.applications_dir() / (base + ".desktop")).string(),
        (paths.icons_dir() / "128x128" / "apps" / (base + ".png")).string(),
        (paths.mime_dir() / "packages" / (base + ".xml")).string(),
    };
    check_lists_equal(result.created_files, expected);
}

TEST_CASE("integrate_app: no file associations means no MIME xml") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    lexe::Manifest m = fixture_manifest();
    m.file_associations.clear();

    const auto result = lexe::desktop::integrate_app(
        paths, m, home.path() / "no-such-icons");

    const std::vector<std::string> expected = {
        (paths.applications_dir() / "lexe-com.example.hello.desktop").string(),
    };
    check_lists_equal(result.created_files, expected);
}

TEST_CASE("integrate_app: integration.desktopEntry=false skips the desktop "
          "entry but keeps icons and MIME") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    lexe::Manifest m = fixture_manifest();
    m.integration_desktop_entry = false;
    const fs::path icons = home.path() / "staging-icons";
    lexe::util::spit(icons / "64.png", std::string_view("png-64-bytes"));

    const auto result = lexe::desktop::integrate_app(paths, m, icons);

    const std::string base = "lexe-com.example.hello";
    const std::vector<std::string> expected = {
        (paths.icons_dir() / "64x64" / "apps" / (base + ".png")).string(),
        (paths.mime_dir() / "packages" / (base + ".xml")).string(),
    };
    check_lists_equal(result.created_files, expected);
}

// ---------------------------------------------------------------------------
// integrate_runtime — `lexe integrate` (application/x-lexe handler).
// ---------------------------------------------------------------------------

TEST_CASE("integrate_runtime returns the runtime's would-create list") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    const auto result = lexe::desktop::integrate_runtime(paths);

    const std::vector<std::string> expected = {
        (paths.applications_dir() / "lexe-installer.desktop").string(),
        (paths.mime_dir() / "packages" / "lexe.xml").string(),
    };
    check_lists_equal(result.created_files, expected);
    for (const auto& f : result.created_files) {
        CHECK(fs::path(f).is_absolute());
    }

#ifdef _WIN32
    CHECK(result.status == lexe::desktop::IntegrationStatus::skipped);
    for (const auto& f : result.created_files) {
        CAPTURE(f);
        CHECK_FALSE(fs::exists(fs::path(f)));
    }
#else
    CHECK(result.status == lexe::desktop::IntegrationStatus::applied);
    CHECK_EQ(lexe::util::slurp_text(paths.applications_dir() /
                                    "lexe-installer.desktop"),
             lexe::desktop::runtime_desktop_entry_text());
    CHECK_EQ(lexe::util::slurp_text(paths.mime_dir() / "packages" / "lexe.xml"),
             lexe::desktop::runtime_mime_xml_text());
#endif
}

// ---------------------------------------------------------------------------
// remove_integration.
// ---------------------------------------------------------------------------

TEST_CASE("remove_integration ignores missing files on every platform") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();

    const std::vector<std::string> ghost_files = {
        (paths.applications_dir() / "lexe-com.example.ghost.desktop").string(),
        (paths.icons_dir() / "64x64" / "apps" / "lexe-com.example.ghost.png")
            .string(),
        (paths.mime_dir() / "packages" / "lexe-com.example.ghost.xml").string(),
    };
    CHECK_NOTHROW(lexe::desktop::remove_integration(paths, ghost_files));
    CHECK_NOTHROW(lexe::desktop::remove_integration(paths, {}));
}

#ifndef _WIN32
// ---------------------------------------------------------------------------
// Linux-only: files actually written, content correct, removal works.
// ---------------------------------------------------------------------------

TEST_CASE("integrate_app writes desktop entry, icons and MIME xml with the "
          "generated content (Linux)") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    const lexe::Manifest m = fixture_manifest();
    const fs::path icons = make_icons_dir(home.path() / "staging-icons");

    const auto result = lexe::desktop::integrate_app(paths, m, icons);
    REQUIRE(result.status == lexe::desktop::IntegrationStatus::applied);

    const std::string base = "lexe-com.example.hello";
    CHECK_EQ(lexe::util::slurp_text(paths.applications_dir() /
                                    (base + ".desktop")),
             lexe::desktop::desktop_entry_text(m));
    CHECK_EQ(lexe::util::slurp_text(paths.mime_dir() / "packages" /
                                    (base + ".xml")),
             lexe::desktop::mime_xml_text(m));
    // Icon bytes copied verbatim into the hicolor layout.
    CHECK_EQ(lexe::util::slurp_text(paths.icons_dir() / "64x64" / "apps" /
                                    (base + ".png")),
             "png-64-bytes");
    CHECK_EQ(lexe::util::slurp_text(paths.icons_dir() / "128x128" / "apps" /
                                    (base + ".png")),
             "png-128-bytes");
    CHECK_EQ(lexe::util::slurp_text(paths.icons_dir() / "256x256" / "apps" /
                                    (base + ".png")),
             "png-256-bytes");
    CHECK_EQ(lexe::util::slurp_text(paths.icons_dir() / "scalable" / "apps" /
                                    (base + ".svg")),
             "<svg/>");

    // Idempotent: integrating again overwrites and reports the same list.
    const auto again = lexe::desktop::integrate_app(paths, m, icons);
    check_lists_equal(again.created_files, result.created_files);
}

TEST_CASE("remove_integration deletes previously created files (Linux)") {
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    const lexe::Manifest m = fixture_manifest();
    const fs::path icons = make_icons_dir(home.path() / "staging-icons");

    const auto result = lexe::desktop::integrate_app(paths, m, icons);
    REQUIRE(result.status == lexe::desktop::IntegrationStatus::applied);
    for (const auto& f : result.created_files) {
        REQUIRE(fs::exists(fs::path(f)));
    }

    lexe::desktop::remove_integration(paths, result.created_files);
    for (const auto& f : result.created_files) {
        CAPTURE(f);
        CHECK_FALSE(fs::exists(fs::path(f)));
    }
    // Removing again (all missing now) is not an error.
    CHECK_NOTHROW(lexe::desktop::remove_integration(paths,
                                                    result.created_files));
}
#endif // !_WIN32

} // TEST_SUITE("desktop")

// desktop module tests (ARCHITECTURE.md #Tests). This module generates the
// `.desktop` and shared-mime-info DOCUMENTS and nothing else, so most of this
// file is exact string output for the fixture manifest, verified on every
// platform. The rest pins that the writing half stays where it now lives —
// DesktopIntegration — and that packaging/ keeps delegating to the runtime
// rather than growing a second implementation back.
//
// Every test case that touches paths constructs lexe::test::TempLexeHome
// first: no test touches the real user profile, and none may leave an entry
// in the developer's own ~/.local/share/applications.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/desktop.hpp"
#include "core/integration.hpp"
#include "core/manifest.hpp"
#include "core/paths.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <utility>
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

std::size_t count_occurrences(const std::string& text,
                              const std::string& needle) {
    std::size_t n = 0;
    for (std::size_t pos = text.find(needle); pos != std::string::npos;
         pos = text.find(needle, pos + needle.size())) {
        ++n;
    }
    return n;
}

/// RAII save/restore for one environment variable, so the XDG cases below can
/// clear LEXE_HOME without leaking that into any later test case.
class EnvGuard {
public:
    explicit EnvGuard(std::string name)
        : name_(std::move(name)), previous_(lexe::util::get_env(name_)) {}
    ~EnvGuard() {
        if (previous_.has_value()) {
            lexe::util::set_env(name_, *previous_);
        } else {
            lexe::util::unset_env(name_);
        }
    }
    EnvGuard(const EnvGuard&) = delete;
    EnvGuard& operator=(const EnvGuard&) = delete;

private:
    std::string name_;
    std::optional<std::string> previous_;
};

/// True when `p` is `root` or lies beneath it. Used to prove that a confined
/// integration wrote nothing outside its temp LEXE_HOME.
bool is_under(const fs::path& p, const fs::path& root) {
    const auto rel = p.lexically_relative(root);
    return !rel.empty() && rel.native()[0] != '.';
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

// ---------------------------------------------------------------------------
// ONE implementation of desktop registration.
//
// Two of them used to exist. This module planned and wrote a handler entry and
// a MIME document for `application/x-lexe`, packaging/install.sh hand-rolled a
// third copy in shell, and `DesktopIntegration` (core/integration.hpp) wrote
// the canonical `application/vnd.usha.lexe` registration the runtime actually
// claims. Which registration a machine ended up with depended on which of them
// ran last — and `doctor --repair` could not put back something a different
// implementation had created.
//
// The writing half of this module is gone; these cases pin that it stays gone,
// and that the shipped scripts keep delegating to the runtime rather than
// growing a copy back.
// ---------------------------------------------------------------------------

TEST_CASE("this module generates documents and registers nothing") {
    // A grep with a compiler behind it: the header exposes content generation
    // and nothing that writes, plans, or registers.
    const std::string header =
        lexe::util::slurp_text(fs::path(LEXE_SOURCE_DIR) / "src" / "core" /
                               "desktop.hpp");
    for (const char* gone : {"integrate_app", "integrate_runtime",
                             "remove_integration", "runtime_desktop_entry_text",
                             "runtime_mime_xml_text", "IntegrationResult",
                             "IntegrationStatus"}) {
        CAPTURE(gone);
        CHECK(header.find(gone) == std::string::npos);
    }
    const std::string impl =
        lexe::util::slurp_text(fs::path(LEXE_SOURCE_DIR) / "src" / "core" /
                               "desktop.cpp");
    // Nothing in here touches the filesystem or spawns the freedesktop tools.
    for (const char* gone : {"util::spit", "write_atomic", "run_process",
                             "update-mime-database", "update-desktop-database",
                             "fs::create_directories", "fs::remove"}) {
        CAPTURE(gone);
        CHECK(impl.find(gone) == std::string::npos);
    }
}

TEST_CASE("packaging/ delegates registration to the runtime instead of "
          "hand-rolling it") {
    const fs::path packaging = fs::path(LEXE_SOURCE_DIR) / "packaging";
    const std::string install = lexe::util::slurp_text(packaging / "install.sh");
    const std::string uninstall =
        lexe::util::slurp_text(packaging / "uninstall.sh");

    // The one way registration happens, and the one way it is undone.
    CHECK(install.find("lexe\" integrate") != std::string::npos);
    CHECK(uninstall.find("integrate --remove") != std::string::npos);

    // …and NOT a second implementation in shell.
    for (const char* hand_rolled :
         {"<mime-info", "xdg-mime default", "[Desktop Entry]"}) {
        CAPTURE(hand_rolled);
        CHECK(install.find(hand_rolled) == std::string::npos);
    }

    // No MIME document ships beside the scripts either: the runtime is the
    // only thing that knows what the document says.
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(packaging, ec)) {
        CAPTURE(entry.path().string());
        CHECK(entry.path().extension() != ".xml");
    }
}

TEST_CASE("the canonical .lexe type is the runtime's, and the alpha's is only "
          "an alias") {
    // `application/x-lexe` was this module's type. It survives as an alias so
    // already-registered desktops and existing files keep resolving, but the
    // type .LEXE claims is the canonical one.
    CHECK_EQ(std::string(lexe::DesktopIntegration::canonical_mime_type()),
             "application/vnd.usha.lexe");
    CHECK_EQ(std::string(lexe::DesktopIntegration::legacy_mime_type()),
             "application/x-lexe");
}

TEST_CASE("registration under LEXE_HOME writes nothing outside it") {
    // Confinement is what lets this suite run on a machine someone is using:
    // a test run must never leave an entry in the developer's own
    // ~/.local/share/applications, and must never take over their .lexe files.
    lexe::test::TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    REQUIRE(paths.desktop_scope() == lexe::DesktopScope::confined);

    lexe::DesktopIntegration integration(paths);
    const lexe::IntegrationReport report = integration.install_runtime_handler();

    REQUIRE_FALSE(report.checks.empty());
    for (const lexe::ArtifactCheck& check : report.checks) {
        CAPTURE(check.artifact.path);
        CHECK(is_under(fs::path(check.artifact.path), home.path()));
    }
    // Every registration is recorded, so `doctor` can name it and repair it.
    const lexe::IntegrationState state = lexe::IntegrationState::load(paths);
    CHECK_EQ(state.artifacts.size(), report.checks.size());
}

} // TEST_SUITE("desktop")

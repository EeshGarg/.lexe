// http module tests — file:// and plain-path sources only; NO network in
// tests (ARCHITECTURE.md #Modules, FORMAT-0.1 §7).

#include <doctest/doctest.h>

#include "core/error.hpp"
#include "core/http.hpp"
#include "core/util.hpp"
#include "helpers.hpp"

#include <string>
#include <vector>

using namespace lexe;
namespace fs = std::filesystem;

namespace {

/// Build a file:// URL from a filesystem path, percent-encoding spaces.
std::string to_file_url(const fs::path& p) {
    std::string s = p.generic_string();
    if (s.empty() || s[0] != '/') s.insert(s.begin(), '/'); // "C:/…" -> "/C:/…"
    std::string encoded;
    for (const char c : s) {
        if (c == ' ') {
            encoded += "%20";
        } else {
            encoded += c;
        }
    }
    return "file://" + encoded;
}

} // namespace

TEST_SUITE("http") {

TEST_CASE("fetch_bytes from a plain filesystem path") {
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "src.bin";
    const std::vector<std::uint8_t> data = {0x00, 0x01, 0xff, 'a', '\n'};
    util::spit(src, data);
    CHECK(http::fetch_bytes(src.string()) == data);
}

TEST_CASE("fetch_bytes from a file:// URL") {
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "update.json";
    util::spit(src, std::string_view("{\"ok\":true}"));
    const auto bytes = http::fetch_bytes(to_file_url(src));
    CHECK(std::string(bytes.begin(), bytes.end()) == "{\"ok\":true}");
}

TEST_CASE("file:// URLs are percent-decoded") {
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "my update.json";
    util::spit(src, std::string_view("spaced"));
    const std::string url = to_file_url(src);
    REQUIRE(url.find("%20") != std::string::npos);
    const auto bytes = http::fetch_bytes(url);
    CHECK(std::string(bytes.begin(), bytes.end()) == "spaced");
}

TEST_CASE("fetch_to_file copies and creates parent directories") {
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "package.lexe";
    const std::vector<std::uint8_t> data = {'P', 'K', 0x03, 0x04, 0x00};
    util::spit(src, data);

    const fs::path dest = home.path() / "cache" / "nested" / "pkg.lexe";
    http::fetch_to_file(to_file_url(src), dest);
    CHECK(util::slurp(dest) == data);

    // Overwrites an existing destination.
    util::spit(src, std::string_view("v2"));
    http::fetch_to_file(src.string(), dest);
    CHECK(util::slurp_text(dest) == "v2");
}

TEST_CASE("missing local sources throw NotFoundError") {
    lexe::test::TempLexeHome home;
    const fs::path ghost = home.path() / "ghost.bin";
    CHECK_THROWS_AS(http::fetch_bytes(ghost.string()), NotFoundError);
    CHECK_THROWS_AS(http::fetch_bytes(to_file_url(ghost)), NotFoundError);
    CHECK_THROWS_AS(http::fetch_to_file(ghost.string(), home.path() / "d.bin"),
                    NotFoundError);
    // A directory is not a fetchable source.
    CHECK_THROWS_AS(http::fetch_bytes(home.path().string()), NotFoundError);
}

} // TEST_SUITE("http")

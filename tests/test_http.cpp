// http module tests — file:// and plain-path sources only; NO network in
// tests (ARCHITECTURE.md #Modules, FORMAT-0.1 §7).

#include <doctest/doctest.h>

#include "lexe/base/error.hpp"
#include "lexe/base/http.hpp"
#include "lexe/base/util.hpp"
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

/// For the cases that are not about the limit. A fetch has no default limit on
/// purpose -- "no limit" was the defect, so the caller always states one.
constexpr http::Limit kAny{16ull * 1024 * 1024};

} // namespace

TEST_SUITE("http") {

TEST_CASE("fetch_bytes from a plain filesystem path") {
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "src.bin";
    const std::vector<std::uint8_t> data = {0x00, 0x01, 0xff, 'a', '\n'};
    util::spit(src, data);
    CHECK(http::fetch_bytes(src.string(), kAny) == data);
}

TEST_CASE("fetch_bytes from a file:// URL") {
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "update.json";
    util::spit(src, std::string_view("{\"ok\":true}"));
    const auto bytes = http::fetch_bytes(to_file_url(src), kAny);
    CHECK(std::string(bytes.begin(), bytes.end()) == "{\"ok\":true}");
}

TEST_CASE("file:// URLs are percent-decoded") {
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "my update.json";
    util::spit(src, std::string_view("spaced"));
    const std::string url = to_file_url(src);
    REQUIRE(url.find("%20") != std::string::npos);
    const auto bytes = http::fetch_bytes(url, kAny);
    CHECK(std::string(bytes.begin(), bytes.end()) == "spaced");
}

TEST_CASE("fetch_to_file copies and creates parent directories") {
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "package.lexe";
    const std::vector<std::uint8_t> data = {'P', 'K', 0x03, 0x04, 0x00};
    util::spit(src, data);

    const fs::path dest = home.path() / "cache" / "nested" / "pkg.lexe";
    http::fetch_to_file(to_file_url(src), dest, kAny);
    CHECK(util::slurp(dest) == data);

    // Overwrites an existing destination.
    util::spit(src, std::string_view("v2"));
    http::fetch_to_file(src.string(), dest, kAny);
    CHECK(util::slurp_text(dest) == "v2");
}

TEST_CASE("missing local sources throw NotFoundError") {
    lexe::test::TempLexeHome home;
    const fs::path ghost = home.path() / "ghost.bin";
    CHECK_THROWS_AS(http::fetch_bytes(ghost.string(), kAny), NotFoundError);
    CHECK_THROWS_AS(http::fetch_bytes(to_file_url(ghost), kAny), NotFoundError);
    CHECK_THROWS_AS(http::fetch_to_file(ghost.string(), home.path() / "d.bin", kAny),
                    NotFoundError);
    // A directory is not a fetchable source.
    CHECK_THROWS_AS(http::fetch_bytes(home.path().string(), kAny), NotFoundError);
}

TEST_CASE("a source larger than the caller's limit is refused before it is read") {
    // REGRESSION. `update.json`'s 1 MiB budget was enforced by the PARSER, and
    // the document had already been fetched into memory by then -- so a source
    // serving 256 MiB had it read in full, and the first complaint was about
    // the signature length. A limit that fires after the allocation it was
    // meant to prevent is decoration, and this one fired after authentication
    // had not yet happened at all.
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "big.json";
    util::spit(src, std::vector<std::uint8_t>(64 * 1024, 'x'));

    // Comfortably under: fine.
    CHECK(http::fetch_bytes(src.string(), {128 * 1024}).size() == 64 * 1024);

    // Over: refused, and the message says which limit and how far over, because
    // "download failed" would send someone to look at their network.
    CHECK_THROWS_WITH_AS(http::fetch_bytes(src.string(), {32 * 1024}),
                         doctest::Contains("exceeds"), lexe::Error);
    CHECK_THROWS_AS(
        http::fetch_to_file(src.string(), home.path() / "out.json", {32 * 1024}),
        lexe::Error);

    // And the destination must not exist afterwards: refusing and then leaving
    // the bytes on disk would defeat the point.
    CHECK_FALSE(fs::exists(home.path() / "out.json"));
}

TEST_CASE("a plaintext http:// source is refused") {
    // FORMAT-0.1 §7 says an update source is https://. The reader accepted
    // http:// identically. A signature still proves WHO wrote an update, so
    // this is not what stops a forgery -- it is what stops an observer learning
    // which applications a user runs, and what keeps §7.1's freeze attack
    // available only to whoever operates the source rather than to anyone on
    // the path.
    CHECK_THROWS_AS(http::require_secure_url("http://example.invalid/u.json"),
                    lexe::Error);
    CHECK_THROWS_WITH_AS(http::require_secure_url("http://example.invalid/u.json"),
                         doctest::Contains("plaintext"), lexe::Error);

    // https, file:// and plain paths are all fine: the last two have no
    // transport to protect, and they are what the tests use.
    CHECK_NOTHROW(http::require_secure_url("https://example.invalid/u.json"));
    CHECK_NOTHROW(http::require_secure_url("file:///tmp/u.json"));
    CHECK_NOTHROW(http::require_secure_url("/tmp/u.json"));

    // Case matters less than the prefix: a scheme is lowercase in practice, and
    // this check is defence in depth behind curl's own --proto-redir.
    CHECK_THROWS_AS(http::require_secure_url("http://127.0.0.1:8080/u.json"),
                    lexe::Error);
}

} // TEST_SUITE("http")

// util module tests (ARCHITECTURE.md #Tests).

#include <doctest/doctest.h>

#include "core/error.hpp"
#include "core/util.hpp"
#include "helpers.hpp"

#include <cctype>
#include <string>
#include <vector>

using namespace lexe;
namespace fs = std::filesystem;

TEST_SUITE("util") {

TEST_CASE("hex encode known vectors") {
    lexe::test::TempLexeHome home;
    CHECK(util::hex_encode(std::vector<std::uint8_t>{}) == "");
    CHECK(util::hex_encode({0x00}) == "00");
    CHECK(util::hex_encode({0x00, 0xff}) == "00ff");
    CHECK(util::hex_encode({0xde, 0xad, 0xbe, 0xef}) == "deadbeef");
    // Digests must be lowercase (FORMAT-0.1 §3).
    CHECK(util::hex_encode({0xAB, 0xCD}) == "abcd");
}

TEST_CASE("hex decode round-trip and case-insensitivity") {
    lexe::test::TempLexeHome home;
    const std::vector<std::uint8_t> data = {0x00, 0x01, 0x7f, 0x80, 0xff};
    CHECK(util::hex_decode(util::hex_encode(data)) == data);
    CHECK(util::hex_decode("DEADbeef") ==
          std::vector<std::uint8_t>{0xde, 0xad, 0xbe, 0xef});
    CHECK(util::hex_decode("") == std::vector<std::uint8_t>{});
}

TEST_CASE("hex decode rejects malformed input") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(util::hex_decode("abc"), Error);   // odd length
    CHECK_THROWS_AS(util::hex_decode("zz"), Error);    // bad digit
    CHECK_THROWS_AS(util::hex_decode("0 "), Error);    // whitespace
}

TEST_CASE("base64 encode RFC 4648 vectors (with padding)") {
    lexe::test::TempLexeHome home;
    auto enc = [](const std::string& s) {
        return util::base64_encode(
            reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    };
    CHECK(enc("") == "");
    CHECK(enc("f") == "Zg==");
    CHECK(enc("fo") == "Zm8=");
    CHECK(enc("foo") == "Zm9v");
    CHECK(enc("foob") == "Zm9vYg==");
    CHECK(enc("fooba") == "Zm9vYmE=");
    CHECK(enc("foobar") == "Zm9vYmFy");
}

TEST_CASE("base64 decode round-trip incl. binary") {
    lexe::test::TempLexeHome home;
    std::vector<std::uint8_t> data;
    for (int i = 0; i < 256; ++i) data.push_back(static_cast<std::uint8_t>(i));
    CHECK(util::base64_decode(util::base64_encode(data)) == data);
    CHECK(util::base64_decode("") == std::vector<std::uint8_t>{});
    CHECK(util::base64_decode("Zm9vYmFy") ==
          std::vector<std::uint8_t>{'f', 'o', 'o', 'b', 'a', 'r'});
}

TEST_CASE("base64 decode is strict") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(util::base64_decode("Zg"), Error);      // missing padding
    CHECK_THROWS_AS(util::base64_decode("Zg="), Error);     // bad length
    CHECK_THROWS_AS(util::base64_decode("Z===") , Error);   // over-padded
    CHECK_THROWS_AS(util::base64_decode("Zg=a"), Error);    // '=' mid-input
    CHECK_THROWS_AS(util::base64_decode("Zm9v!A=="), Error); // bad char
    CHECK_THROWS_AS(util::base64_decode("Zm 9v"), Error);   // whitespace
}

TEST_CASE("slurp/spit round-trip binary data and create parents") {
    lexe::test::TempLexeHome home;
    const fs::path file = home.path() / "a" / "b" / "data.bin";
    std::vector<std::uint8_t> data = {0x00, 0x01, 0xff, 0x00, 'x', '\n', 0x7f};
    util::spit(file, data);
    CHECK(util::slurp(file) == data);

    util::spit(file, std::string_view("hello\n"));
    CHECK(util::slurp_text(file) == "hello\n");

    // empty file
    util::spit(file, std::vector<std::uint8_t>{});
    CHECK(util::slurp(file).empty());
}

TEST_CASE("slurp missing file throws NotFoundError") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(util::slurp(home.path() / "nope.bin"), NotFoundError);
}

TEST_CASE("copy_recursive and remove_recursive") {
    lexe::test::TempLexeHome home;
    const fs::path src = home.path() / "src";
    util::spit(src / "one.txt", std::string_view("1"));
    util::spit(src / "sub" / "two.txt", std::string_view("2"));

    const fs::path dst = home.path() / "dst";
    util::copy_recursive(src, dst);
    CHECK(util::slurp_text(dst / "one.txt") == "1");
    CHECK(util::slurp_text(dst / "sub" / "two.txt") == "2");

    // overwrite existing
    util::spit(src / "one.txt", std::string_view("1b"));
    util::copy_recursive(src, dst);
    CHECK(util::slurp_text(dst / "one.txt") == "1b");

    util::remove_recursive(dst);
    CHECK(!fs::exists(dst));
    CHECK_NOTHROW(util::remove_recursive(dst)); // missing is fine

    CHECK_THROWS_AS(util::copy_recursive(home.path() / "ghost", dst),
                    NotFoundError);
}

TEST_CASE("get_env/set_env/unset_env round-trip") {
    lexe::test::TempLexeHome home;
    const std::string name = "LEXE_TEST_ENV_VAR";
    util::set_env(name, "value one");
    REQUIRE(util::get_env(name).has_value());
    CHECK(*util::get_env(name) == "value one");
    util::set_env(name, "two");
    CHECK(*util::get_env(name) == "two");
    util::unset_env(name);
    CHECK(!util::get_env(name).has_value());
}

TEST_CASE("run_process captures stdout") {
    lexe::test::TempLexeHome home;
#ifdef _WIN32
    const auto r = util::run_process({"cmd", "/c", "echo hello"});
#else
    const auto r = util::run_process({"sh", "-c", "echo hello"});
#endif
    CHECK(r.exit_code == 0);
    CHECK(r.stdout_text.find("hello") != std::string::npos);
}

TEST_CASE("run_process propagates exit codes") {
    lexe::test::TempLexeHome home;
#ifdef _WIN32
    const auto r = util::run_process({"cmd", "/c", "exit 3"});
#else
    const auto r = util::run_process({"sh", "-c", "exit 3"});
#endif
    CHECK(r.exit_code == 3);
}

TEST_CASE("run_process argv args with spaces survive quoting (no shell)") {
    lexe::test::TempLexeHome home;
    // Write a file whose content is one argv element containing spaces and
    // quotes, then read it back — proves the argument reached the child
    // intact through the platform quoting rules.
#ifdef _WIN32
    // The whole command is ONE argv element with spaces; it reaches cmd as a
    // single /c argument only if run_process quotes it correctly.
    const fs::path out = home.path() / "out.txt";
    util::RunOptions opts;
    opts.cwd = home.path();
    const auto r = util::run_process(
        {"cmd", "/c", "echo hello spaced world> out.txt"}, opts);
    CHECK(r.exit_code == 0);
    CHECK(util::slurp_text(out).find("hello spaced world") != std::string::npos);
#else
    const fs::path out = home.path() / "argv out.txt";
    const auto r = util::run_process(
        {"sh", "-c", "printf '%s' \"$1\" > \"$2\"", "sh",
         "hello spaced \"quoted\" world", out.string()});
    CHECK(r.exit_code == 0);
    CHECK(util::slurp_text(out) == "hello spaced \"quoted\" world");
#endif
}

TEST_CASE("run_process honours cwd") {
    lexe::test::TempLexeHome home;
    const fs::path sub = home.path() / "cwd-test";
    fs::create_directories(sub);
    util::RunOptions opts;
    opts.cwd = sub;
#ifdef _WIN32
    const auto r = util::run_process({"cmd", "/c", "cd"}, opts);
#else
    const auto r = util::run_process({"pwd"}, opts);
#endif
    CHECK(r.exit_code == 0);
    // Compare canonical forms: the child prints its cwd.
    std::string printed = r.stdout_text;
    while (!printed.empty() && (printed.back() == '\n' || printed.back() == '\r')) {
        printed.pop_back();
    }
    CHECK(fs::weakly_canonical(fs::path(printed)) == fs::weakly_canonical(sub));
}

TEST_CASE("run_process throws for unlaunchable programs") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(
        util::run_process({"lexe-definitely-not-a-real-program-12345"}),
        Error);
    CHECK_THROWS_AS(util::run_process({}), Error);
}

TEST_CASE("now_utc_string is RFC 3339 UTC") {
    lexe::test::TempLexeHome home;
    const std::string t = util::now_utc_string();
    REQUIRE(t.size() == 20);
    CHECK(t[4] == '-');
    CHECK(t[7] == '-');
    CHECK(t[10] == 'T');
    CHECK(t[13] == ':');
    CHECK(t[16] == ':');
    CHECK(t[19] == 'Z');
    for (const std::size_t i : {0u, 1u, 2u, 3u, 5u, 6u, 8u, 9u, 11u, 12u,
                                14u, 15u, 17u, 18u}) {
        CHECK(std::isdigit(static_cast<unsigned char>(t[i])) != 0);
    }
    CHECK(t.substr(0, 2) == "20"); // sanity: this century
}

} // TEST_SUITE("util")

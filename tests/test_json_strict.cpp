// json_strict tests (HARDENING.md §E, §F byte budgets): duplicate-key
// rejection at every nesting level, byte-budget boundaries, and proof that
// every security-relevant JSON parser (manifest, key file, installation record)
// rejects duplicate keys. The update.json boundary is proven end-to-end in
// test_updater.cpp; hashes.json/manifest inside a fully-signed package are in
// the malformed-package corpus (test_hostile_packages.cpp).

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/manifest.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

using lexe::json_strict::parse;
using lexe::json_strict::parse_ordered;

namespace {
constexpr std::size_t kBig = 1024 * 1024;
}

TEST_SUITE("json_strict") {

TEST_CASE("accepts well-formed JSON and preserves values") {
    lexe::test::TempLexeHome home;
    const auto doc = parse(R"({"a":1,"b":[1,2,{"c":true}],"d":"x"})", "t", kBig);
    CHECK(doc["a"] == 1);
    CHECK(doc["b"][2]["c"] == true);
    CHECK(doc["d"] == "x");
}

TEST_CASE("rejects a duplicate key at the top level") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(parse(R"({"k":1,"k":2})", "t", kBig), lexe::VerificationError);
    // The message names the offending key.
    CHECK_THROWS_WITH_AS(parse(R"({"publicKey":"a","publicKey":"b"})", "t", kBig),
                         doctest::Contains("duplicate object key \"publicKey\""),
                         lexe::VerificationError);
}

TEST_CASE("rejects a duplicate key in a NESTED object (recursive)") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(parse(R"({"outer":{"x":1,"x":2}})", "t", kBig),
                    lexe::VerificationError);
    CHECK_THROWS_AS(parse(R"({"a":{"b":{"c":1,"c":2}}})", "t", kBig),
                    lexe::VerificationError);
}

TEST_CASE("rejects a duplicate key inside an array element object") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(parse(R"({"list":[{"k":1,"k":2}]})", "t", kBig),
                    lexe::VerificationError);
}

TEST_CASE("the SAME key in DIFFERENT sibling objects is NOT a duplicate") {
    lexe::test::TempLexeHome home;
    CHECK_NOTHROW(parse(R"({"a":{"k":1},"b":{"k":2}})", "t", kBig));
    CHECK_NOTHROW(parse(R"({"list":[{"k":1},{"k":2}]})", "t", kBig));
}

TEST_CASE("rejects malformed JSON and invalid UTF-8") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(parse("this is { not json", "t", kBig),
                    lexe::VerificationError);
    CHECK_THROWS_AS(parse("", "t", kBig), lexe::VerificationError);
    // A lone 0xFF byte is not valid UTF-8.
    const std::string bad = std::string("{\"k\":\"") + '\xFF' + "\"}";
    CHECK_THROWS_AS(parse(bad, "t", kBig), lexe::VerificationError);
}

TEST_CASE("enforces the byte budget: limit-1 / limit / limit+1") {
    lexe::test::TempLexeHome home;
    // Build "{"k":"<pad>"}" documents of exact sizes around a small limit.
    auto doc_of_size = [](std::size_t total) {
        const std::string prefix = R"({"k":")";
        const std::string suffix = R"("})";
        REQUIRE(total >= prefix.size() + suffix.size());
        return prefix + std::string(total - prefix.size() - suffix.size(), 'x') +
               suffix;
    };
    const std::size_t limit = 64;
    CHECK_NOTHROW(parse(doc_of_size(limit - 1), "t", limit)); // under
    CHECK_NOTHROW(parse(doc_of_size(limit), "t", limit));     // exactly at
    CHECK_THROWS_WITH_AS(parse(doc_of_size(limit + 1), "t", limit),
                         doctest::Contains("exceeds"), lexe::VerificationError);
}

TEST_CASE("parse_ordered rejects duplicates and preserves key order") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(parse_ordered(R"({"k":1,"k":2})", "t", kBig),
                    lexe::VerificationError);
    const auto doc = parse_ordered(R"({"z":1,"a":2,"m":3})", "t", kBig);
    std::string order;
    for (auto it = doc.begin(); it != doc.end(); ++it) order += it.key();
    CHECK(order == "zam"); // insertion order preserved, not sorted
}

// ---- proof at each security-relevant parser boundary --------------------

TEST_CASE("Manifest::parse rejects duplicate keys (publisher.publicKey)") {
    lexe::test::TempLexeHome home;
    // A duplicate publicKey is the canonical attack: verifier and reviewer
    // could otherwise disagree about which key signed the package.
    const char* dup = R"({
      "lexeVersion":"0.1","id":"com.example.app","name":"App","version":"1.0.0",
      "publisher":{"name":"P","publicKey":"ed25519:AAAA","publicKey":"ed25519:BBBB"},
      "applicationType":"native","architectures":["x86_64"],
      "entrypoint":{"executable":"bin/app"},
      "install":{"scope":"user","mode":"bundled"}
    })";
    CHECK_THROWS_AS(lexe::Manifest::parse(std::string_view(dup)),
                    lexe::VerificationError);
}

TEST_CASE("crypto::read_keyfile rejects duplicate keys (privateSeed)") {
    lexe::test::TempLexeHome home;
    const fs::path f = home.path() / "dup.key.json";
    lexe::util::spit(
        f, std::string_view(
               R"({"algorithm":"ed25519","privateSeed":"AAAA","privateSeed":"BBBB"})"));
    CHECK_THROWS_AS(lexe::crypto::read_keyfile(f), lexe::Error);
}

TEST_CASE("InstallationRecord::from_json rejects duplicate keys") {
    lexe::test::TempLexeHome home;
    CHECK_THROWS_AS(
        lexe::InstallationRecord::from_json(R"({"id":"a","id":"b"})"),
        lexe::Error);
    // Nested (createdFiles element / publisherKey) too.
    CHECK_THROWS_AS(lexe::InstallationRecord::from_json(
                        R"({"id":"a","publisherKey":"x","publisherKey":"y"})"),
                    lexe::Error);
}

} // TEST_SUITE("json_strict")

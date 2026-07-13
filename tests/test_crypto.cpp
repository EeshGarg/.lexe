// crypto module tests (ARCHITECTURE.md #Tests): SHA-256 known-answer
// vectors, Ed25519 RFC 8032 known-answer vectors, sign/verify round-trips,
// corrupted-signature rejection, publisher key encode/decode accept/reject
// table (FORMAT-0.1 §4), key file round-trip + 0600 mode (POSIX).
// Every test case constructs lexe::test::TempLexeHome first.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace crypto = lexe::crypto;
namespace util = lexe::util;
namespace fs = std::filesystem;

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

crypto::Seed seed_from_hex(const std::string& hex) {
    const std::vector<std::uint8_t> raw = util::hex_decode(hex);
    REQUIRE(raw.size() == 32);
    crypto::Seed out{};
    std::copy(raw.begin(), raw.end(), out.begin());
    return out;
}

crypto::PublicKey pubkey_from_hex(const std::string& hex) {
    const std::vector<std::uint8_t> raw = util::hex_decode(hex);
    REQUIRE(raw.size() == 32);
    crypto::PublicKey out{};
    std::copy(raw.begin(), raw.end(), out.begin());
    return out;
}

crypto::Signature sig_from_hex(const std::string& hex) {
    const std::vector<std::uint8_t> raw = util::hex_decode(hex);
    REQUIRE(raw.size() == 64);
    crypto::Signature out{};
    std::copy(raw.begin(), raw.end(), out.begin());
    return out;
}

std::string sig_to_hex(const crypto::Signature& sig) {
    return util::hex_encode(sig.data(), sig.size());
}

} // namespace

TEST_SUITE("crypto") {

// ---------------------------------------------------------------------------
// SHA-256 (FORMAT-0.1 §3: lowercase hex)
// ---------------------------------------------------------------------------

TEST_CASE("SHA-256 known-answer vectors over bytes") {
    lexe::test::TempLexeHome home;

    // NIST/FIPS 180-2 known answers.
    const std::string empty_digest =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const std::string abc_digest =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const std::string two_block_digest =
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    CHECK(crypto::sha256_hex(bytes_of("")) == empty_digest);
    CHECK(crypto::sha256_hex(nullptr, 0) == empty_digest);
    CHECK(crypto::sha256_hex(bytes_of("abc")) == abc_digest);
    CHECK(crypto::sha256_hex(bytes_of(
              "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
          two_block_digest);

    // Pointer/length overload agrees with the vector overload.
    const std::vector<std::uint8_t> abc = bytes_of("abc");
    CHECK(crypto::sha256_hex(abc.data(), abc.size()) == abc_digest);

    // Digests are lowercase hex, 64 chars.
    const std::string d = crypto::sha256_hex(bytes_of("Lexe"));
    CHECK(d.size() == 64);
    CHECK(d.find_first_not_of("0123456789abcdef") == std::string::npos);
}

TEST_CASE("SHA-256 of files is streamed and matches known answers") {
    lexe::test::TempLexeHome home;

    const fs::path small = home.path() / "abc.bin";
    util::spit(small, std::string_view("abc"));
    CHECK(crypto::sha256_file_hex(small) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // One million 'a' (FIPS 180-2 test 3) — larger than the 64 KiB read
    // chunk, so this exercises the streaming path across many chunks.
    const fs::path big = home.path() / "million-a.bin";
    util::spit(big, std::string(1000 * 1000, 'a'));
    CHECK(crypto::sha256_file_hex(big) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    // Empty file hashes like the empty message.
    const fs::path empty = home.path() / "empty.bin";
    util::spit(empty, std::string_view(""));
    CHECK(crypto::sha256_file_hex(empty) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // File and byte hashing agree on identical content.
    CHECK(crypto::sha256_file_hex(small) == crypto::sha256_hex(bytes_of("abc")));

    CHECK_THROWS_AS(crypto::sha256_file_hex(home.path() / "does-not-exist"),
                    lexe::NotFoundError);
}

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032 §7.1 known-answer vectors)
// ---------------------------------------------------------------------------

TEST_CASE("Ed25519 RFC 8032 known-answer vectors (derive, sign, verify)") {
    lexe::test::TempLexeHome home;

    struct Vector {
        const char* name;
        const char* seed_hex;   // RFC "SECRET KEY" (32-byte seed)
        const char* public_hex; // RFC "PUBLIC KEY"
        const char* message_hex;
        const char* signature_hex;
    };
    const Vector vectors[] = {
        {"RFC 8032 TEST 1 (empty message)",
         "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"RFC 8032 TEST 2 (one byte)",
         "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
        {"RFC 8032 TEST 3 (two bytes)",
         "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
    };

    for (const Vector& v : vectors) {
        CAPTURE(v.name);
        const crypto::Seed seed = seed_from_hex(v.seed_hex);
        const crypto::PublicKey expected_pub = pubkey_from_hex(v.public_hex);
        const std::vector<std::uint8_t> message = util::hex_decode(v.message_hex);
        const crypto::Signature expected_sig = sig_from_hex(v.signature_hex);

        // Public key derivation from the seed matches the RFC.
        const crypto::KeyPair kp = crypto::keypair_from_seed(seed);
        CHECK(kp.public_key == expected_pub);
        CHECK(kp.seed == seed);

        // Deterministic signature matches the RFC byte for byte.
        const crypto::Signature sig = crypto::sign(message, kp);
        CHECK(sig_to_hex(sig) == sig_to_hex(expected_sig));

        // And the RFC signature verifies under the RFC public key.
        CHECK(crypto::verify_signature(message, expected_sig, expected_pub));
    }
}

TEST_CASE("keygen from OS entropy and sign/verify round-trips") {
    lexe::test::TempLexeHome home;

    const crypto::KeyPair kp = crypto::generate_keypair();

    // The pair is internally consistent: re-deriving from the seed yields
    // the same public key (FORMAT-0.1 §4: re-derived on every use).
    CHECK(crypto::keypair_from_seed(kp.seed).public_key == kp.public_key);

    // Two generations produce distinct keys (entropy sanity check).
    const crypto::KeyPair other = crypto::generate_keypair();
    CHECK(kp.seed != other.seed);
    CHECK(kp.public_key != other.public_key);

    // Round-trips: empty, short, and multi-block messages.
    std::vector<std::vector<std::uint8_t>> messages;
    messages.push_back(bytes_of(""));
    messages.push_back(bytes_of("hello lexe"));
    std::vector<std::uint8_t> big(10 * 1024);
    for (std::size_t i = 0; i < big.size(); ++i) {
        big[i] = static_cast<std::uint8_t>(i * 31 + 7);
    }
    messages.push_back(big);

    for (const auto& message : messages) {
        CAPTURE(message.size());
        const crypto::Signature sig = crypto::sign(message, kp);
        CHECK(crypto::verify_signature(message, sig, kp.public_key));
        // The wrong key never verifies.
        CHECK_FALSE(crypto::verify_signature(message, sig, other.public_key));
    }
}

TEST_CASE("corrupted signatures and tampered messages are rejected") {
    lexe::test::TempLexeHome home;

    const crypto::KeyPair kp = crypto::generate_keypair();
    const std::vector<std::uint8_t> message = bytes_of("signed lexe.json bytes");
    const crypto::Signature good = crypto::sign(message, kp);
    REQUIRE(crypto::verify_signature(message, good, kp.public_key));

    // Flip a single bit at several positions across both signature halves.
    for (const std::size_t pos : {std::size_t{0}, std::size_t{31},
                                  std::size_t{32}, std::size_t{63}}) {
        CAPTURE(pos);
        crypto::Signature bad = good;
        bad[pos] = static_cast<std::uint8_t>(bad[pos] ^ 0x01);
        CHECK_FALSE(crypto::verify_signature(message, bad, kp.public_key));
    }

    // All-zero signature is rejected.
    const crypto::Signature zero{};
    CHECK_FALSE(crypto::verify_signature(message, zero, kp.public_key));

    // A tampered message fails under the genuine signature.
    std::vector<std::uint8_t> tampered = message;
    tampered[0] ^= 0x01;
    CHECK_FALSE(crypto::verify_signature(tampered, good, kp.public_key));

    // A truncated/extended message fails too.
    std::vector<std::uint8_t> shorter(message.begin(), message.end() - 1);
    CHECK_FALSE(crypto::verify_signature(shorter, good, kp.public_key));
    std::vector<std::uint8_t> longer = message;
    longer.push_back(0x00);
    CHECK_FALSE(crypto::verify_signature(longer, good, kp.public_key));

    // A tampered public key never verifies (and never throws).
    crypto::PublicKey bad_key = kp.public_key;
    bad_key[0] = static_cast<std::uint8_t>(bad_key[0] ^ 0x01);
    CHECK_FALSE(crypto::verify_signature(message, good, bad_key));
}

// ---------------------------------------------------------------------------
// Publisher key string (FORMAT-0.1 §4: "ed25519:" + padded base64, 32 bytes)
// ---------------------------------------------------------------------------

TEST_CASE("publisher key string: encode format and accept table") {
    lexe::test::TempLexeHome home;

    // All-zero key: 32 zero bytes are 43 'A' plus one '=' of padding.
    const crypto::PublicKey zero{};
    const std::string zero_encoded = crypto::encode_public_key(zero);
    CHECK(zero_encoded == "ed25519:" + std::string(43, 'A') + "=");
    CHECK(crypto::decode_public_key(zero_encoded) == zero);

    // RFC 8032 TEST 1 public key round-trips through the string form.
    const crypto::PublicKey rfc = pubkey_from_hex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const std::string rfc_encoded = crypto::encode_public_key(rfc);
    CHECK(rfc_encoded.substr(0, 8) == "ed25519:");
    CHECK(rfc_encoded.size() == 8 + 44); // base64(32 bytes) is 44 chars padded
    CHECK(rfc_encoded.back() == '=');
    CHECK(crypto::decode_public_key(rfc_encoded) == rfc);

    // Generated keys round-trip as well.
    const crypto::KeyPair kp = crypto::generate_keypair();
    CHECK(crypto::decode_public_key(crypto::encode_public_key(kp.public_key)) ==
          kp.public_key);

    // Any structurally valid 32-byte value is accepted (0xff pattern).
    const std::vector<std::uint8_t> ff(32, 0xff);
    const std::string ff_encoded = "ed25519:" + util::base64_encode(ff);
    const crypto::PublicKey ff_decoded = crypto::decode_public_key(ff_encoded);
    CHECK(std::all_of(ff_decoded.begin(), ff_decoded.end(),
                      [](std::uint8_t b) { return b == 0xff; }));
}

TEST_CASE("publisher key string: reject table") {
    lexe::test::TempLexeHome home;

    const std::string b64_32 =
        util::base64_encode(std::vector<std::uint8_t>(32, 0x42));
    const std::string b64_31 =
        util::base64_encode(std::vector<std::uint8_t>(31, 0x42));
    const std::string b64_33 =
        util::base64_encode(std::vector<std::uint8_t>(33, 0x42));
    std::string unpadded = b64_32;
    while (!unpadded.empty() && unpadded.back() == '=') unpadded.pop_back();

    const std::string rejects[] = {
        "",                          // empty
        "ed25519",                   // prefix without colon
        "ed25519:",                  // empty base64 → decoded length 0
        "ED25519:" + b64_32,         // prefix is case-sensitive
        "Ed25519:" + b64_32,         // prefix is case-sensitive
        "rsa:" + b64_32,             // wrong algorithm
        ":" + b64_32,                // colon but no algorithm
        b64_32,                      // missing prefix entirely
        " ed25519:" + b64_32,        // leading whitespace
        "ed25519: " + b64_32,        // whitespace after the colon
        "ed25519:" + b64_31,         // decoded length 31
        "ed25519:" + b64_33,         // decoded length 33
        "ed25519:" + unpadded,       // padding is REQUIRED (RFC 4648 w/ pad)
        "ed25519:" + b64_32 + "=",   // over-padded / bad length
        "ed25519:!!!!",              // invalid base64 characters
        "ed25519:" + std::string(43, 'A') + "\n=", // embedded whitespace
        "ed25519:AAAA AAAA",         // interior space
    };

    for (const std::string& s : rejects) {
        CAPTURE(s);
        CHECK_THROWS_AS(crypto::decode_public_key(s), lexe::VerificationError);
    }
}

// ---------------------------------------------------------------------------
// Key files (FORMAT-0.1 §4 "Key files": JSON, 0600 on POSIX)
// ---------------------------------------------------------------------------

TEST_CASE("key file write/read round-trip and JSON shape") {
    lexe::test::TempLexeHome home;

    const crypto::KeyPair kp = crypto::generate_keypair();
    const fs::path file = home.path() / "keys" / "publisher.json";
    crypto::write_keyfile(file, kp); // creates the parent directory
    REQUIRE(fs::exists(file));

    // Exact FORMAT-0.1 §4 shape: {algorithm, publicKey, privateSeed}.
    const nlohmann::json j = nlohmann::json::parse(util::slurp_text(file));
    REQUIRE(j.is_object());
    CHECK(j.at("algorithm").get<std::string>() == "ed25519");
    CHECK(j.at("publicKey").get<std::string>() ==
          crypto::encode_public_key(kp.public_key));
    const std::vector<std::uint8_t> seed_bytes =
        util::base64_decode(j.at("privateSeed").get<std::string>());
    REQUIRE(seed_bytes.size() == 32);
    CHECK(std::equal(seed_bytes.begin(), seed_bytes.end(), kp.seed.begin()));

#ifndef _WIN32
    // FORMAT-0.1 §4: MUST be created with mode 0600 on POSIX.
    const fs::perms p = fs::status(file).permissions();
    CHECK((p & (fs::perms::group_all | fs::perms::others_all)) ==
          fs::perms::none);
    CHECK((p & fs::perms::owner_read) != fs::perms::none);
    CHECK((p & fs::perms::owner_write) != fs::perms::none);
#endif

    // Reading re-derives the same pair from the stored seed.
    const crypto::KeyPair loaded = crypto::read_keyfile(file);
    CHECK(loaded.seed == kp.seed);
    CHECK(loaded.public_key == kp.public_key);

    // Overwriting with a different key replaces the contents.
    const crypto::KeyPair other = crypto::generate_keypair();
    crypto::write_keyfile(file, other);
    CHECK(crypto::read_keyfile(file).public_key == other.public_key);

    // The tests/helpers.hpp factory produces a loadable key file too.
    const fs::path helper_file = lexe::test::make_keyfile(home.path() / "h");
    const crypto::KeyPair helper_kp = crypto::read_keyfile(helper_file);
    CHECK(crypto::keypair_from_seed(helper_kp.seed).public_key ==
          helper_kp.public_key);
}

TEST_CASE("key file rejects missing and malformed inputs") {
    lexe::test::TempLexeHome home;

    CHECK_THROWS_AS(crypto::read_keyfile(home.path() / "missing.json"),
                    lexe::NotFoundError);

    const auto write_and_expect_error = [&](const std::string& name,
                                            const std::string& content) {
        const fs::path f = home.path() / name;
        util::spit(f, std::string_view(content));
        CAPTURE(name);
        CHECK_THROWS_AS(crypto::read_keyfile(f), lexe::Error);
        // ...but never as "not found": the file exists, it is malformed.
        CHECK_THROWS_WITH_AS(crypto::read_keyfile(f),
                             doctest::Contains("read_keyfile"), lexe::Error);
    };

    const crypto::KeyPair kp = crypto::generate_keypair();
    const std::string good_seed_b64 =
        util::base64_encode(kp.seed.data(), kp.seed.size());

    write_and_expect_error("not-json.json", "this is not json {");
    write_and_expect_error("not-object.json", "[1, 2, 3]");
    write_and_expect_error("wrong-algo.json",
                           nlohmann::json{{"algorithm", "rsa"},
                                          {"privateSeed", good_seed_b64}}
                               .dump());
    write_and_expect_error("missing-algo.json",
                           nlohmann::json{{"privateSeed", good_seed_b64}}
                               .dump());
    write_and_expect_error(
        "missing-seed.json",
        nlohmann::json{{"algorithm", "ed25519"},
                       {"publicKey",
                        crypto::encode_public_key(kp.public_key)}}
            .dump());
    write_and_expect_error("seed-not-string.json",
                           nlohmann::json{{"algorithm", "ed25519"},
                                          {"privateSeed", 12345}}
                               .dump());
    write_and_expect_error("seed-bad-base64.json",
                           nlohmann::json{{"algorithm", "ed25519"},
                                          {"privateSeed", "!!not-base64!!"}}
                               .dump());
    write_and_expect_error(
        "seed-wrong-length.json",
        nlohmann::json{{"algorithm", "ed25519"},
                       {"privateSeed",
                        util::base64_encode(
                            std::vector<std::uint8_t>(16, 0x01))}}
            .dump());

    // A publicKey that does not match the seed is corruption, not a valid file.
    const crypto::KeyPair other = crypto::generate_keypair();
    write_and_expect_error(
        "pubkey-mismatch.json",
        nlohmann::json{{"algorithm", "ed25519"},
                       {"publicKey",
                        crypto::encode_public_key(other.public_key)},
                       {"privateSeed", good_seed_b64}}
            .dump());
    write_and_expect_error(
        "pubkey-garbage.json",
        nlohmann::json{{"algorithm", "ed25519"},
                       {"publicKey", "not-a-key"},
                       {"privateSeed", good_seed_b64}}
            .dump());
}

} // TEST_SUITE("crypto")

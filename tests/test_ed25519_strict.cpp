// Strict Ed25519 verification (HARDENING.md §G). Positive known-answer vectors
// for sign/verify live in test_crypto.cpp (RFC 8032 §7.1); this suite adds the
// NEGATIVE vectors the strict pre-checks must reject: signature malleability
// (S + L), non-canonical / degenerate public-key encodings, exact-length
// enforcement, and single-bit tampering of R and S.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/package/crypto.hpp"

#include <ed25519/ed25519.h> // the PREVIOUS provider, for cross-provider fixtures

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using namespace lexe;

namespace {

// Ed25519 group order L, little-endian (same constant crypto.cpp checks S < L).
constexpr std::uint8_t kL[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/// Return sig with its scalar S replaced by S + L (little-endian add). S < L, so
/// S + L < 2^254 and no 256-bit overflow occurs. orlp's verifier accepts this
/// malleated form; the strict canonical-S check must reject it.
crypto::Signature add_L_to_scalar(const crypto::Signature& sig) {
    crypto::Signature out = sig;
    unsigned carry = 0;
    for (int i = 0; i < 32; ++i) {
        const unsigned v = sig[32 + i] + kL[i] + carry;
        out[32 + i] = static_cast<std::uint8_t>(v & 0xff);
        carry = v >> 8;
    }
    return out;
}

} // namespace

TEST_SUITE("ed25519_strict") {

TEST_CASE("a valid signature verifies, and S+L malleability is REJECTED") {
    lexe::test::TempLexeHome home;
    const crypto::KeyPair key = lexe::test::make_keypair();
    const std::vector<std::uint8_t> msg = {'h', 'a', 'r', 'd', 'e', 'n'};
    const crypto::Signature sig = crypto::sign(msg, key);

    // Sanity: the canonical signature verifies.
    CHECK(crypto::verify_signature(msg, sig, key.public_key));

    // The malleated signature (S -> S+L) shares the same R and satisfies the
    // raw verification equation, but S+L >= L is non-canonical and MUST fail.
    const crypto::Signature malleated = add_L_to_scalar(sig);
    CHECK(malleated != sig);
    CHECK_FALSE(crypto::verify_signature(msg, malleated, key.public_key));
}

TEST_CASE("a non-canonical public-key encoding (y >= p) is rejected") {
    lexe::test::TempLexeHome home;
    const crypto::KeyPair key = lexe::test::make_keypair();
    const std::vector<std::uint8_t> msg = {'x'};
    const crypto::Signature sig = crypto::sign(msg, key);

    // y = all-ones with the sign bit cleared is 2^255-1 >= p (= 2^255-19).
    crypto::PublicKey noncanonical{};
    for (auto& b : noncanonical) b = 0xff;
    noncanonical[31] = 0x7f;
    CHECK_FALSE(crypto::verify_signature(msg, sig, noncanonical));
}

TEST_CASE("the all-zero (degenerate small-order) public key is rejected") {
    lexe::test::TempLexeHome home;
    const std::vector<std::uint8_t> msg = {'x'};
    crypto::Signature sig{}; // any signature
    crypto::PublicKey zero{}; // all zero
    CHECK_FALSE(crypto::verify_signature(msg, sig, zero));
}

TEST_CASE("the identity-point key verifies nothing: the forgery is refused") {
    // REGRESSION. With publicKey = the identity point (01 00..00), the
    // signature R = identity, S = 0 satisfies [S]B = R + [k]A for EVERY
    // message, because A contributes nothing. The vendored verifier accepted
    // it; only the all-zero key was refused. Found by conformance corpus case
    // `key-identity-point` on a build without libsodium.
    lexe::test::TempLexeHome home;
    crypto::PublicKey identity{};
    identity[0] = 0x01;
    crypto::Signature forged{};
    forged[0] = 0x01; // R = identity, S = 0
    for (const std::vector<std::uint8_t>& msg :
         {std::vector<std::uint8_t>{'a'}, std::vector<std::uint8_t>{'z', 'z'}}) {
        CHECK_FALSE(crypto::verify_signature(msg, forged, identity));
    }
    // The raw curve check really would have passed: that is the bug.
    const unsigned char m = 'a';
    CHECK(ed25519_verify(forged.data(), &m, 1, identity.data()) != 0);
}

TEST_CASE("every small-order public key and every small-order R is rejected") {
    lexe::test::TempLexeHome home;
    const crypto::KeyPair key = lexe::test::make_keypair();
    const std::vector<std::uint8_t> msg = {'s', 'o'};
    const crypto::Signature sig = crypto::sign(msg, key);
    REQUIRE(crypto::verify_signature(msg, sig, key.public_key));

    // The 8 small-order points (and their y = p, p+1 spellings), each with
    // both x-sign bits.
    std::vector<crypto::PublicKey> small;
    const auto add = [&](std::initializer_list<std::uint8_t> head, std::uint8_t fill,
                         std::uint8_t last) {
        crypto::PublicKey k{};
        std::fill(k.begin(), k.end(), fill);
        std::size_t i = 0;
        for (const std::uint8_t b : head) k[i++] = b;
        k[31] = last;
        small.push_back(k);
        k[31] = static_cast<std::uint8_t>(last | 0x80);
        small.push_back(k);
    };
    add({0x00}, 0x00, 0x00);
    add({0x01}, 0x00, 0x00);
    add({0xec}, 0xff, 0x7f);
    add({0xed}, 0xff, 0x7f);
    add({0xee}, 0xff, 0x7f);
    small.push_back({0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
                     0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
                     0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05});
    small.push_back({0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
                     0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
                     0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a});
    for (const crypto::PublicKey& k : small) {
        CAPTURE(k[0]);
        CHECK_FALSE(crypto::verify_signature(msg, sig, k));
        crypto::Signature bad_r = sig;
        std::copy(k.begin(), k.end(), bad_r.begin());
        CHECK_FALSE(crypto::verify_signature(msg, bad_r, key.public_key));
    }
}

TEST_CASE("flipping any bit of R or S breaks verification") {
    lexe::test::TempLexeHome home;
    const crypto::KeyPair key = lexe::test::make_keypair();
    const std::vector<std::uint8_t> msg = {'d', 'a', 't', 'a'};
    const crypto::Signature sig = crypto::sign(msg, key);
    REQUIRE(crypto::verify_signature(msg, sig, key.public_key));

    for (std::size_t byte : {std::size_t{0}, std::size_t{31}, std::size_t{32},
                             std::size_t{40}}) {
        crypto::Signature tampered = sig;
        tampered[byte] ^= 0x01;
        CAPTURE(byte);
        CHECK_FALSE(crypto::verify_signature(msg, tampered, key.public_key));
    }
}

TEST_CASE("cross-provider compatibility with the previous orlp/ed25519 signer") {
    lexe::test::TempLexeHome home;
    // A fixed seed makes this a deterministic known-answer fixture: standard
    // Ed25519 (RFC 8032) derives one public key and one signature per seed, so
    // orlp and the migrated provider must agree byte-for-byte.
    crypto::Seed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(i + 1);
    }
    const std::vector<std::uint8_t> msg = {'l', 'e', 'x', 'e', '-', 'x'};

    // Sign with the OLD provider (orlp) directly, as the pre-migration builder
    // did.
    unsigned char pk[32];
    unsigned char sk[64];
    ed25519_create_keypair(pk, sk, seed.data());
    crypto::Signature orlp_sig{};
    ed25519_sign(orlp_sig.data(), msg.data(), msg.size(), pk, sk);
    crypto::PublicKey pubkey{};
    std::copy(pk, pk + 32, pubkey.begin());

    // The migrated provider derives the SAME public key from the seed...
    CHECK(crypto::keypair_from_seed(seed).public_key == pubkey);
    // ...verifies the OLD provider's signature (a package signed by the old
    // builder still verifies through the new path)...
    CHECK(crypto::verify_signature(msg, orlp_sig, pubkey));
    // ...and produces a byte-identical signature (deterministic Ed25519), so a
    // package signed through the new path verifies everywhere too.
    CHECK(crypto::sign(msg, crypto::keypair_from_seed(seed)) == orlp_sig);
}

TEST_CASE("decode_public_key requires exactly 32 decoded bytes") {
    lexe::test::TempLexeHome home;
    // 31 and 33 zero bytes, base64-encoded, must both be rejected.
    CHECK_THROWS_AS(
        crypto::decode_public_key("ed25519:" +
                                  lexe::util::base64_encode(
                                      std::vector<std::uint8_t>(31, 0).data(), 31)),
        lexe::VerificationError);
    CHECK_THROWS_AS(
        crypto::decode_public_key("ed25519:" +
                                  lexe::util::base64_encode(
                                      std::vector<std::uint8_t>(33, 0).data(), 33)),
        lexe::VerificationError);
}

} // TEST_SUITE("ed25519_strict")

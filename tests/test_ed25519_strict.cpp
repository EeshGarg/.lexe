// Strict Ed25519 verification (HARDENING.md §G). Positive known-answer vectors
// for sign/verify live in test_crypto.cpp (RFC 8032 §7.1); this suite adds the
// NEGATIVE vectors the strict pre-checks must reject: signature malleability
// (S + L), non-canonical / degenerate public-key encodings, exact-length
// enforcement, and single-bit tampering of R and S.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/crypto.hpp"

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

// trust model tests (runtime-trust WS3): fingerprints, strict trust-record
// parsing, and the evaluate() classification for every signature/key state.
// Persistence-into-install and enforcement live in later commits.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/trust.hpp"
#include "core/util.hpp"

#include <optional>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

constexpr const char* kId = "com.example.hello";

std::string enc(const crypto::KeyPair& k) {
    return crypto::encode_public_key(k.public_key);
}

/// A valid on-disk trust record JSON for `id` bound to `key`.
std::string good_record_json(const std::string& id, const crypto::KeyPair& key) {
    TrustRecord r;
    r.schema_version = 1;
    r.app_id = id;
    r.public_key = enc(key);
    r.fingerprint = key_fingerprint(key.public_key).full;
    r.first_seen = "2026-01-01T00:00:00Z";
    r.last_seen = "2026-01-01T00:00:00Z";
    r.trust_provenance = "install-accept";
    return r.to_json();
}

} // namespace

TEST_SUITE("trust") {

// ------------------------------------------------------------- fingerprint

TEST_CASE("fingerprint: derived from canonical key bytes, deterministic vector") {
    crypto::PublicKey zero{}; // 32 zero bytes
    const Fingerprint fp = key_fingerprint(zero);

    // The fingerprint IS the SHA-256 of the raw public-key bytes.
    CHECK(fp.full == crypto::sha256_hex(zero.data(), zero.size()));
    // Pinned deterministic vector (SHA-256 of 32 zero bytes).
    CHECK(fp.full ==
          "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");
    // Grouped display: uppercase, spaced quads.
    CHECK(fp.grouped ==
          "6668 7AAD F862 BD77 6C8F C18B 8E9F 8E20 0897 1485 6EE2 33B3 902A "
          "591D 0D5F 2925");
    CHECK(fp.short_id == "6668 7AAD F862 BD77 6C8F");
}

TEST_CASE("fingerprint: distinct keys give distinct fingerprints") {
    const crypto::KeyPair a = test::make_keypair();
    const crypto::KeyPair b = test::make_keypair();
    CHECK(key_fingerprint(a.public_key).full != key_fingerprint(b.public_key).full);
    // The encoded-string overload agrees with the raw-key overload.
    CHECK(key_fingerprint(enc(a)).full == key_fingerprint(a.public_key).full);
}

// -------------------------------------------------- strict record parsing

TEST_CASE("trust record: round-trips and strictly rejects corruption") {
    const crypto::KeyPair key = test::make_keypair();
    const std::string good = good_record_json(kId, key);
    CHECK_NOTHROW(TrustRecord::from_json(good));
    const TrustRecord parsed = TrustRecord::from_json(good);
    CHECK(parsed.app_id == kId);
    CHECK(parsed.public_key == enc(key));

    SUBCASE("duplicate keys are rejected") {
        std::string dup = good;
        const std::string needle = "\"appId\":";
        dup.insert(dup.find(needle), "\"appId\": \"x\",\n  ");
        CHECK_THROWS_AS(TrustRecord::from_json(dup), CorruptTrustError);
    }
    SUBCASE("fingerprint mismatch is rejected") {
        TrustRecord r = TrustRecord::from_json(good);
        r.fingerprint = std::string(64, 'a');
        CHECK_THROWS_AS(TrustRecord::from_json(r.to_json()), CorruptTrustError);
    }
    SUBCASE("a non-Ed25519 publicKey is rejected") {
        TrustRecord r = TrustRecord::from_json(good);
        r.public_key = "ed25519:not-base64!!";
        CHECK_THROWS_AS(TrustRecord::from_json(r.to_json()), CorruptTrustError);
    }
    SUBCASE("a keyless record that is not a block is rejected") {
        TrustRecord r = TrustRecord::from_json(good);
        r.public_key.clear();
        r.fingerprint.clear();
        r.blocked = false;
        CHECK_THROWS_AS(TrustRecord::from_json(r.to_json()), CorruptTrustError);
    }
    SUBCASE("garbage is rejected") {
        CHECK_THROWS_AS(TrustRecord::from_json("{ not json"), CorruptTrustError);
    }
}

// ---------------------------------------------------- store read defenses

TEST_CASE("trust store: read fails closed on App-ID substitution") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const TrustStore store(paths);
    const crypto::KeyPair key = test::make_keypair();

    // A record whose appId names ANOTHER application, placed at this id's path.
    util::spit(registry.trust_record_file(kId),
               std::string_view(good_record_json("com.example.other", key)));
    CHECK_THROWS_AS(store.read(kId), CorruptTrustError);
}

// ---------------------------------------------------- evaluate() states

TEST_CASE("evaluate: first-seen valid signature allows a consented first install") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const TrustStore store(paths);
    const crypto::KeyPair key = test::make_keypair();

    const TrustEvaluation e =
        store.evaluate(kId, key.public_key, SignatureState::Valid, std::nullopt);
    CHECK(e.signature == SignatureState::Valid);
    CHECK(e.key_state == PublisherKeyState::FirstSeen);
    CHECK(e.decision == TrustDecision::AllowFirstInstall);
    CHECK(e.allowed());
    CHECK(e.needs_first_install_consent());
    CHECK_NOTHROW(e.throw_if_rejected());
}

TEST_CASE("evaluate: an invalid signature is never allowed, even first-seen") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const TrustStore store(paths);
    const crypto::KeyPair key = test::make_keypair();

    const TrustEvaluation e = store.evaluate(kId, key.public_key,
                                             SignatureState::Invalid, std::nullopt);
    CHECK(e.decision == TrustDecision::RejectInvalidSignature);
    CHECK_FALSE(e.allowed());
    CHECK_THROWS_AS(e.throw_if_rejected(), VerificationError);
}

TEST_CASE("evaluate: known matching and explicitly-trusted keys") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    TrustStore store(paths);
    const crypto::KeyPair key = test::make_keypair();

    store.record_accept(kId, key.public_key, /*explicit_trust=*/false,
                        "install-accept");
    TrustEvaluation known =
        store.evaluate(kId, key.public_key, SignatureState::Valid, std::nullopt);
    CHECK(known.key_state == PublisherKeyState::KnownMatching);
    CHECK(known.decision == TrustDecision::AllowKnownUpdate);
    CHECK(known.allowed());
    CHECK_FALSE(known.needs_first_install_consent());

    store.record_accept(kId, key.public_key, /*explicit_trust=*/true,
                        "trust-command");
    TrustEvaluation trusted =
        store.evaluate(kId, key.public_key, SignatureState::Valid, std::nullopt);
    CHECK(trusted.key_state == PublisherKeyState::ExplicitlyTrusted);
    CHECK(trusted.explicitly_trusted);
}

TEST_CASE("evaluate: a changed key is rejected without a bypass") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    TrustStore store(paths);
    const crypto::KeyPair a = test::make_keypair();
    const crypto::KeyPair b = test::make_keypair();

    store.record_accept(kId, a.public_key, false, "install-accept");
    const TrustEvaluation e =
        store.evaluate(kId, b.public_key, SignatureState::Valid, std::nullopt);
    CHECK(e.key_state == PublisherKeyState::Changed);
    CHECK(e.decision == TrustDecision::RejectChangedKey);
    REQUIRE(e.expected.has_value());
    CHECK(e.expected->full == key_fingerprint(a.public_key).full);
    CHECK(e.presented.full == key_fingerprint(b.public_key).full);
    CHECK_THROWS_AS(e.throw_if_rejected(), ChangedKeyError);
}

TEST_CASE("evaluate: a locally blocked App ID is rejected for any key") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    TrustStore store(paths);
    const crypto::KeyPair key = test::make_keypair();

    store.block(kId);
    const TrustEvaluation e =
        store.evaluate(kId, key.public_key, SignatureState::Valid, std::nullopt);
    CHECK(e.key_state == PublisherKeyState::Blocked);
    CHECK(e.revocation == RevocationState::LocallyBlocked);
    CHECK(e.decision == TrustDecision::RejectBlocked);
    CHECK_THROWS_AS(e.throw_if_rejected(), BlockedKeyError);
}

TEST_CASE("evaluate: a corrupt trust record fails closed") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const TrustStore store(paths);
    const crypto::KeyPair key = test::make_keypair();

    util::spit(registry.trust_record_file(kId), std::string_view("{ corrupt"));
    const TrustEvaluation e =
        store.evaluate(kId, key.public_key, SignatureState::Valid, std::nullopt);
    CHECK(e.key_state == PublisherKeyState::TrustUnavailable);
    CHECK(e.decision == TrustDecision::RejectCorruptTrust);
    CHECK_THROWS_AS(e.throw_if_rejected(), CorruptTrustError);
}

TEST_CASE("evaluate: retained data under another key blocks a first install") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const TrustStore store(paths);
    const crypto::KeyPair a = test::make_keypair();
    const crypto::KeyPair b = test::make_keypair();

    const TrustEvaluation e = store.evaluate(
        kId, b.public_key, SignatureState::Valid, std::optional<std::string>(enc(a)));
    CHECK(e.key_state == PublisherKeyState::RetainedDataConflict);
    CHECK(e.decision == TrustDecision::RejectRetainedDataConflict);
    CHECK_THROWS_AS(e.throw_if_rejected(), RetainedDataConflict);
}

// ------------------------------------------------ persistence + block ops

TEST_CASE("store: record_accept persists atomically and is idempotent") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    TrustStore store(paths);
    const crypto::KeyPair key = test::make_keypair();

    CHECK_FALSE(store.exists(kId));
    store.record_accept(kId, key.public_key, false, "install-accept");
    REQUIRE(store.exists(kId));
    const TrustRecord r1 = store.read(kId).value();
    CHECK(r1.public_key == enc(key));
    CHECK_FALSE(r1.explicitly_trusted);

    // Second accept keeps first_seen, may set explicit trust.
    store.record_accept(kId, key.public_key, true, "trust-command");
    const TrustRecord r2 = store.read(kId).value();
    CHECK(r2.first_seen == r1.first_seen);
    CHECK(r2.explicitly_trusted);
}

TEST_CASE("store: block, unblock, forget") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    TrustStore store(paths);
    const crypto::KeyPair key = test::make_keypair();

    store.record_accept(kId, key.public_key, false, "install-accept");
    store.block(kId);
    CHECK(store.read(kId).value().blocked);

    store.unblock(kId);
    CHECK_FALSE(store.read(kId).value().blocked);
    CHECK(store.read(kId).value().public_key == enc(key)); // binding preserved

    store.forget(kId);
    CHECK_FALSE(store.exists(kId));

    // Blocking an unknown id creates a keyless block; unblocking then drops it.
    store.block("com.example.unknown");
    CHECK(store.read("com.example.unknown").value().blocked);
    store.unblock("com.example.unknown");
    CHECK_FALSE(store.exists("com.example.unknown"));
}

TEST_CASE("trust errors map to CLI exit code 7") {
    CHECK(exit_code_for(ChangedKeyError("x")) == 7);
    CHECK(exit_code_for(BlockedKeyError("x")) == 7);
    CHECK(exit_code_for(CorruptTrustError("x")) == 7);
    CHECK(exit_code_for(TrustError("x")) == 7);
}

} // TEST_SUITE("trust")

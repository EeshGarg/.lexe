#pragma once
// crypto — SHA-256 hashing (FORMAT-0.1 §3), Ed25519 signatures and publisher
// key encoding (FORMAT-0.1 §4), key files (FORMAT-0.1 §4 "Key files").
// Backed by vendored PicoSHA2 and orlp/ed25519.

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace lexe::crypto {

using PublicKey = std::array<std::uint8_t, 32>; // raw Ed25519 public key
using Seed = std::array<std::uint8_t, 32>;      // raw Ed25519 private seed
using Signature = std::array<std::uint8_t, 64>; // raw Ed25519 signature

/// SHA-256 of a byte buffer, lowercase hex (FORMAT-0.1 §3).
std::string sha256_hex(const std::uint8_t* data, std::size_t len);
std::string sha256_hex(const std::vector<std::uint8_t>& data);

/// SHA-256 of a file, streamed (never loads the whole file), lowercase hex.
/// Throws NotFoundError if the file does not exist.
std::string sha256_file_hex(const std::filesystem::path& file);

/// An Ed25519 keypair. Per FORMAT-0.1 §4 the pair is re-derived from the
/// 32-byte seed on every use; only {public_key, seed} are ever persisted.
struct KeyPair {
    PublicKey public_key{};
    Seed seed{};
};

/// Generate a fresh keypair from OS entropy. Throws Error when the entropy
/// source fails.
KeyPair generate_keypair();

/// Re-derive the public key from a seed (used when loading key files).
KeyPair keypair_from_seed(const Seed& seed);

/// Sign `message` (raw entry bytes — FORMAT-0.1 §4 signs bytes, never parsed
/// structures) with the pair derived from `key.seed`.
Signature sign(const std::vector<std::uint8_t>& message, const KeyPair& key);

/// Verify a raw 64-byte signature. Returns false on mismatch (never throws
/// for a mere bad signature).
bool verify_signature(const std::vector<std::uint8_t>& message,
                      const Signature& signature, const PublicKey& public_key);

/// Encode a public key as the manifest string "ed25519:" + base64 with
/// padding (FORMAT-0.1 §4 "Publisher key encoding").
std::string encode_public_key(const PublicKey& key);

/// Whether two encoded publisher keys are the SAME KEY.
///
/// Compares decoded 32-byte key material, never the strings. Trust pinning asks
/// "is this the same publisher?", which is a question about the key, and a
/// string comparison answers a different question: "is this the same spelling?".
///
/// Canonical encoding is separately required by `decode_public_key`, so in a
/// well-formed package the two questions currently coincide. They are kept apart
/// anyway, because the consequence of them diverging is not a cosmetic mismatch:
/// it is an installed application refusing every legitimate update from its own
/// publisher, or -- if the comparison were ever relaxed the other way -- a
/// different publisher taking over an installed id. A security decision should
/// not rest on an encoding rule enforced somewhere else.
///
/// Returns false when either side fails to decode. A key that cannot be read is
/// not equal to anything, including another unreadable key.
bool same_public_key(const std::string& a, const std::string& b);

/// Decode a publisher key string. Throws VerificationError on a wrong prefix,
/// bad base64, or decoded length != 32 (FORMAT-0.1 §4).
PublicKey decode_public_key(const std::string& encoded);

/// Write a `lexe keygen` JSON key file {algorithm, publicKey, privateSeed}
/// (FORMAT-0.1 §4 "Key files"). Created with mode 0600 on POSIX.
void write_keyfile(const std::filesystem::path& file, const KeyPair& key);

/// Read a key file and re-derive the pair from its seed. Throws NotFoundError
/// if missing, Error on malformed contents.
KeyPair read_keyfile(const std::filesystem::path& file);

} // namespace lexe::crypto

// crypto — SHA-256 hashing (FORMAT-0.1 §3), Ed25519 signatures and publisher
// key encoding (FORMAT-0.1 §4), key files (FORMAT-0.1 §4 "Key files").
// Backed by vendored PicoSHA2 and orlp/ed25519. See crypto.hpp for contracts.

#include "core/crypto.hpp"

#include "core/error.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/util.hpp"

#include <ed25519/ed25519.h>
#include <nlohmann/json.hpp>
#include <picosha2/picosha2.h>

#if defined(LEXE_HAVE_SODIUM)
#include <sodium.h>
#endif

#include <algorithm>
#include <cstring>
#include <fstream>
#include <string_view>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
// clang-format off
#include <bcrypt.h> // needs windows.h first
// clang-format on
#pragma comment(lib, "bcrypt")
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

namespace lexe::crypto {

namespace {

/// Best-effort scrub of secret material so expanded private keys and seeds do
/// not linger in freed memory (ARCHITECTURE.md security invariant #5).
void secure_wipe(void* p, std::size_t n) {
    volatile std::uint8_t* v = static_cast<volatile std::uint8_t*>(p);
    for (std::size_t i = 0; i < n; ++i) v[i] = 0;
}

/// Fill `buf` with `len` bytes of OS entropy: BCryptGenRandom on Windows,
/// getrandom(2) with a /dev/urandom fallback on Linux, /dev/urandom on other
/// POSIX systems. Throws Error when the entropy source fails.
void fill_os_random(std::uint8_t* buf, std::size_t len) {
#if defined(_WIN32)
    const NTSTATUS status = BCryptGenRandom(
        nullptr, buf, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw Error("crypto: BCryptGenRandom failed (status " +
                    std::to_string(static_cast<long>(status)) + ")");
    }
#else
    std::size_t got = 0;
#if defined(__linux__)
    while (got < len) {
        const ssize_t r = ::getrandom(buf + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) break; // pre-3.17 kernel: use /dev/urandom
            throw Error(std::string("crypto: getrandom failed: ") +
                        std::strerror(errno));
        }
        got += static_cast<std::size_t>(r);
    }
    if (got == len) return;
#endif
    const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        throw Error("crypto: cannot open /dev/urandom");
    }
    while (got < len) {
        const ssize_t r = ::read(fd, buf + got, len - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            throw Error(std::string("crypto: reading /dev/urandom failed: ") +
                        std::strerror(errno));
        }
        if (r == 0) {
            ::close(fd);
            throw Error("crypto: unexpected EOF from /dev/urandom");
        }
        got += static_cast<std::size_t>(r);
    }
    ::close(fd);
#endif
}

/// ed25519_sign/ed25519_verify receive a message pointer even for an empty
/// message; never hand them nullptr (vector::data() may be null when empty).
const unsigned char* message_ptr(const std::vector<std::uint8_t>& m) {
    static const unsigned char dummy = 0;
    return m.empty() ? &dummy : m.data();
}

#if defined(LEXE_HAVE_SODIUM)
/// libsodium requires one-time initialization before any call. C++11 magic
/// statics make this thread-safe on first use.
void ensure_sodium_init() {
    static const int rc = sodium_init(); // -1 fail, 0 ok, 1 already initialized
    if (rc < 0) {
        throw Error("crypto: libsodium initialization failed");
    }
}
#endif

constexpr std::string_view kKeyPrefix = "ed25519:";

// --------------------------------------------------- strict Ed25519 checks
// The vendored orlp/ed25519 verifier does NOT reject non-canonical signatures
// or point encodings (HARDENING.md §G). We enforce those before calling it:
//   * the signature scalar S (bytes 32..63) must be < L (the group order) —
//     otherwise S and S+L are two signatures for the same message (malleability);
//   * the public key must be a canonically-encoded point (y < p) and not the
//     all-zero small-order point.
// Comprehensive small-order-point rejection is a property of the intended
// libsodium backend (docs/TRUST.md) and is documented as such; these checks are
// the strict guarantees the current backend can be given without curve
// arithmetic, and they never reject a legitimately generated random key.

/// Little-endian 32-byte unsigned comparison: is a < b?
bool le_less_than(const std::uint8_t* a, const std::uint8_t* b) {
    for (int i = 31; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] < b[i];
    }
    return false; // equal
}

/// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493,
/// little-endian.
constexpr std::uint8_t kL[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/// Field prime p = 2^255 - 19, little-endian.
constexpr std::uint8_t kP[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

/// The signature scalar S (the high 32 bytes) is canonical iff S < L.
bool signature_scalar_canonical(const Signature& signature) {
    return le_less_than(signature.data() + 32, kL);
}

/// The public key is a canonical point encoding (y < p) and not the all-zero
/// degenerate small-order point.
bool public_key_canonical(const PublicKey& public_key) {
    bool all_zero = true;
    for (std::size_t i = 0; i < public_key.size(); ++i) {
        if (public_key[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) return false;
    std::uint8_t y[32];
    std::memcpy(y, public_key.data(), 32);
    y[31] &= 0x7f; // strip the x-coordinate sign bit before the y < p compare
    return le_less_than(y, kP);
}

} // namespace

std::string sha256_hex(const std::uint8_t* data, std::size_t len) {
    std::array<std::uint8_t, 32> digest{};
    picosha2::hash256(data, data + len, digest.begin(), digest.end());
    return util::hex_encode(digest.data(), digest.size());
}

std::string sha256_hex(const std::vector<std::uint8_t>& data) {
    return sha256_hex(data.data(), data.size());
}

std::string sha256_file_hex(const std::filesystem::path& file) {
    std::error_code ec;
    if (!std::filesystem::exists(file, ec) || ec) {
        throw NotFoundError("sha256_file_hex: file not found: " + file.string());
    }
    std::ifstream in(file, std::ios::binary);
    if (!in.is_open()) {
        throw Error("sha256_file_hex: cannot open: " + file.string());
    }
    picosha2::hash256_one_by_one hasher;
    std::vector<std::uint8_t> buf(64 * 1024);
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = in.gcount();
        if (n > 0) {
            hasher.process(buf.data(), buf.data() + n);
        }
    }
    if (in.bad()) {
        throw Error("sha256_file_hex: read error: " + file.string());
    }
    hasher.finish();
    std::array<std::uint8_t, 32> digest{};
    hasher.get_hash_bytes(digest.begin(), digest.end());
    return util::hex_encode(digest.data(), digest.size());
}

KeyPair generate_keypair() {
    Seed seed{};
    fill_os_random(seed.data(), seed.size());
    KeyPair kp = keypair_from_seed(seed);
    secure_wipe(seed.data(), seed.size());
    return kp;
}

KeyPair keypair_from_seed(const Seed& seed) {
    KeyPair kp;
    kp.seed = seed;
    unsigned char private_key[64];
    // Both providers implement standard Ed25519, so the same seed derives the
    // same public key — this is what makes packages cross-provider compatible.
#if defined(LEXE_HAVE_SODIUM)
    ensure_sodium_init();
    crypto_sign_ed25519_seed_keypair(kp.public_key.data(), private_key,
                                     seed.data());
#else
    ed25519_create_keypair(kp.public_key.data(), private_key, seed.data());
#endif
    secure_wipe(private_key, sizeof(private_key));
    return kp;
}

Signature sign(const std::vector<std::uint8_t>& message, const KeyPair& key) {
    // FORMAT-0.1 §4: the keypair is re-derived from the seed on every use;
    // the 64-byte expanded private key never leaves this function. Detached
    // signature over the exact message bytes (never a re-serialized structure).
    unsigned char private_key[64];
    Signature sig{};
#if defined(LEXE_HAVE_SODIUM)
    ensure_sodium_init();
    unsigned char public_key[32];
    crypto_sign_ed25519_seed_keypair(public_key, private_key, key.seed.data());
    crypto_sign_ed25519_detached(sig.data(), nullptr, message_ptr(message),
                                 message.size(), private_key);
#else
    unsigned char public_key[32];
    ed25519_create_keypair(public_key, private_key, key.seed.data());
    ed25519_sign(sig.data(), message_ptr(message), message.size(), public_key,
                 private_key);
#endif
    secure_wipe(private_key, sizeof(private_key));
    return sig;
}

bool verify_signature(const std::vector<std::uint8_t>& message,
                      const Signature& signature, const PublicKey& public_key) {
    // Strict pre-checks (HARDENING.md §G) the vendored verifier omits: reject a
    // non-canonical signature scalar (malleability) and a non-canonical or
    // degenerate public-key encoding BEFORE the curve check.
    if (!signature_scalar_canonical(signature)) return false;
    if (!public_key_canonical(public_key)) return false;
#if defined(LEXE_HAVE_SODIUM)
    // libsodium's detached verify additionally rejects non-canonical S and
    // small-order / non-canonical point encodings per its documented API; the
    // checks above are kept as defense-in-depth and for identical negative-
    // vector behaviour across providers.
    ensure_sodium_init();
    return crypto_sign_ed25519_verify_detached(
               signature.data(), message_ptr(message), message.size(),
               public_key.data()) == 0;
#else
    return ed25519_verify(signature.data(), message_ptr(message),
                          message.size(), public_key.data()) != 0;
#endif
}

std::string encode_public_key(const PublicKey& key) {
    return std::string(kKeyPrefix) +
           util::base64_encode(key.data(), key.size());
}

PublicKey decode_public_key(const std::string& encoded) {
    const std::string_view sv(encoded);
    if (sv.substr(0, kKeyPrefix.size()) != kKeyPrefix) {
        throw VerificationError(
            "publisher key: missing \"ed25519:\" prefix: " + encoded);
    }
    std::vector<std::uint8_t> raw;
    try {
        raw = util::base64_decode(sv.substr(kKeyPrefix.size()));
    } catch (const Error& e) {
        throw VerificationError(std::string("publisher key: ") + e.what());
    }
    if (raw.size() != 32) {
        throw VerificationError("publisher key: decoded length is " +
                                std::to_string(raw.size()) + ", expected 32");
    }
    PublicKey key{};
    std::copy(raw.begin(), raw.end(), key.begin());
    return key;
}

void write_keyfile(const std::filesystem::path& file, const KeyPair& key) {
    // Re-derive from the seed so the stored publicKey always matches it (§4).
    const KeyPair derived = keypair_from_seed(key.seed);
    const nlohmann::json j = {
        {"algorithm", "ed25519"},
        {"publicKey", encode_public_key(derived.public_key)},
        {"privateSeed",
         util::base64_encode(derived.seed.data(), derived.seed.size())},
    };
    std::string text = j.dump(2);
    text.push_back('\n');
#if defined(_WIN32)
    util::spit(file, std::string_view(text));
#else
    // FORMAT-0.1 §4: the key file MUST be created with mode 0600. Open with
    // that mode so the seed is never group/other-readable, even transiently;
    // fchmod tightens a pre-existing file too.
    if (file.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(file.parent_path(), ec);
    }
    const int fd = ::open(file.c_str(),
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          S_IRUSR | S_IWUSR);
    if (fd < 0) {
        throw Error("write_keyfile: cannot create: " + file.string());
    }
    if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        ::close(fd);
        throw Error("write_keyfile: cannot set mode 0600: " + file.string());
    }
    std::size_t off = 0;
    while (off < text.size()) {
        const ssize_t w = ::write(fd, text.data() + off, text.size() - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            throw Error("write_keyfile: write failed: " + file.string());
        }
        off += static_cast<std::size_t>(w);
    }
    if (::close(fd) != 0) {
        throw Error("write_keyfile: close failed: " + file.string());
    }
#endif
}

KeyPair read_keyfile(const std::filesystem::path& file) {
    std::error_code ec;
    if (!std::filesystem::exists(file, ec) || ec) {
        throw NotFoundError(
            "no such key file: " + file.string(),
            "Generate a signing keypair with `lexe keygen " + file.string() +
                "`.");
    }
    const std::string text = util::slurp_text(file);
    // Strict parse (HARDENING.md §E): a key file carries signing-key material;
    // reject duplicate keys (e.g. two "privateSeed") rather than pick one.
    const nlohmann::json j =
        json_strict::parse(text, "key file", limits::kMaxKeyfileBytes);
    if (!j.is_object()) {
        throw Error("read_keyfile: not a JSON object: " + file.string());
    }
    if (!j.contains("algorithm") || !j["algorithm"].is_string() ||
        j["algorithm"].get<std::string>() != "ed25519") {
        throw Error("read_keyfile: algorithm must be \"ed25519\": " +
                    file.string());
    }
    if (!j.contains("privateSeed") || !j["privateSeed"].is_string()) {
        throw Error("read_keyfile: missing privateSeed: " + file.string());
    }
    std::vector<std::uint8_t> seed_bytes;
    try {
        seed_bytes = util::base64_decode(j["privateSeed"].get<std::string>());
    } catch (const Error& e) {
        throw Error(std::string("read_keyfile: bad privateSeed base64: ") +
                    e.what());
    }
    if (seed_bytes.size() != 32) {
        secure_wipe(seed_bytes.data(), seed_bytes.size());
        throw Error("read_keyfile: privateSeed must decode to 32 bytes, got " +
                    std::to_string(seed_bytes.size()));
    }
    Seed seed{};
    std::copy(seed_bytes.begin(), seed_bytes.end(), seed.begin());
    secure_wipe(seed_bytes.data(), seed_bytes.size());
    const KeyPair kp = keypair_from_seed(seed);
    secure_wipe(seed.data(), seed.size());
    if (j.contains("publicKey")) {
        PublicKey stored{};
        try {
            if (!j["publicKey"].is_string()) {
                throw Error("not a string");
            }
            stored = decode_public_key(j["publicKey"].get<std::string>());
        } catch (const Error& e) {
            throw Error(std::string("read_keyfile: bad publicKey: ") +
                        e.what());
        }
        if (stored != kp.public_key) {
            throw Error("read_keyfile: publicKey does not match privateSeed: " +
                        file.string());
        }
    }
    return kp;
}

} // namespace lexe::crypto

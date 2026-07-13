// crypto — SHA-256 hashing (FORMAT-0.1 §3), Ed25519 signatures and publisher
// key encoding (FORMAT-0.1 §4), key files (FORMAT-0.1 §4 "Key files").
// Backed by vendored PicoSHA2 and orlp/ed25519. See crypto.hpp for contracts.

#include "core/crypto.hpp"

#include "core/error.hpp"
#include "core/util.hpp"

#include <ed25519/ed25519.h>
#include <nlohmann/json.hpp>
#include <picosha2/picosha2.h>

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

constexpr std::string_view kKeyPrefix = "ed25519:";

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
    ed25519_create_keypair(kp.public_key.data(), private_key, seed.data());
    secure_wipe(private_key, sizeof(private_key));
    return kp;
}

Signature sign(const std::vector<std::uint8_t>& message, const KeyPair& key) {
    // FORMAT-0.1 §4: the keypair is re-derived from the seed on every use;
    // the 64-byte expanded private key never leaves this function.
    unsigned char public_key[32];
    unsigned char private_key[64];
    ed25519_create_keypair(public_key, private_key, key.seed.data());
    Signature sig{};
    ed25519_sign(sig.data(), message_ptr(message), message.size(), public_key,
                 private_key);
    secure_wipe(private_key, sizeof(private_key));
    return sig;
}

bool verify_signature(const std::vector<std::uint8_t>& message,
                      const Signature& signature, const PublicKey& public_key) {
    return ed25519_verify(signature.data(), message_ptr(message),
                          message.size(), public_key.data()) != 0;
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
        throw NotFoundError("read_keyfile: no such key file: " + file.string());
    }
    const std::string text = util::slurp_text(file);
    const nlohmann::json j =
        nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object()) {
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

#pragma once
// Shared test helpers (ARCHITECTURE.md #Tests). Header-only. Every test
// creates a TempLexeHome so LEXE_HOME points into a fresh temp directory —
// no test ever touches the real user profile.
//
// The helpers are deliberately self-contained: key generation, key-file
// writing and public-key encoding go through the vendored primitives
// (orlp/ed25519) plus lexe::util directly, so they work no matter which
// first-party modules have landed. The bytes they produce are exactly what
// FORMAT-0.1 §4 specifies, so they interoperate with lexe::crypto.
// make_test_package uses PackageWriter; tamper_entry uses miniz directly.

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/util.hpp"

#include <ed25519/ed25519.h>
#include <miniz/miniz.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <functional>
#include <optional>
#include <random>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace lexe::test {

namespace fs = std::filesystem;

/// A unique, not-yet-created directory path under the system temp dir.
inline fs::path unique_temp_dir(const std::string& prefix) {
    static std::mt19937_64 rng(
        static_cast<std::uint64_t>(std::random_device{}()) ^
        static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    return fs::temp_directory_path() / (prefix + std::to_string(rng()));
}

/// RAII: creates a fresh temp directory, points LEXE_HOME at it, restores
/// the previous LEXE_HOME value (or unsets it) and deletes the directory on
/// destruction.
class TempLexeHome {
public:
    TempLexeHome() {
        dir_ = unique_temp_dir("lexe-test-home-");
        fs::create_directories(dir_);
        previous_ = util::get_env("LEXE_HOME");
        util::set_env("LEXE_HOME", dir_.string());
    }

    ~TempLexeHome() {
        if (previous_.has_value()) {
            util::set_env("LEXE_HOME", *previous_);
        } else {
            util::unset_env("LEXE_HOME");
        }
        std::error_code ec;
        fs::remove_all(dir_, ec); // best effort
    }

    TempLexeHome(const TempLexeHome&) = delete;
    TempLexeHome& operator=(const TempLexeHome&) = delete;

    const fs::path& path() const { return dir_; }

private:
    fs::path dir_;
    std::optional<std::string> previous_;
};

/// Generate an Ed25519 keypair for tests (vendored ed25519 directly, so it
/// works even while lexe::crypto is unimplemented).
inline crypto::KeyPair make_keypair() {
    crypto::Seed seed{};
    if (ed25519_create_seed(seed.data()) != 0) {
        std::random_device rd; // fallback entropy
        for (auto& b : seed) b = static_cast<std::uint8_t>(rd());
    }
    std::array<unsigned char, 32> pub{};
    std::array<unsigned char, 64> priv{};
    ed25519_create_keypair(pub.data(), priv.data(), seed.data());
    crypto::KeyPair kp;
    std::copy(pub.begin(), pub.end(), kp.public_key.begin());
    kp.seed = seed;
    return kp;
}

/// FORMAT-0.1 §4 publisher key string: "ed25519:" + base64(pub, padded).
inline std::string encode_public_key_str(const crypto::PublicKey& key) {
    return "ed25519:" + util::base64_encode(key.data(), key.size());
}

/// Write `key` as a `lexe keygen` JSON key file (FORMAT-0.1 §4 "Key files").
/// Returns the key file path.
inline fs::path make_keyfile(const fs::path& dir, const crypto::KeyPair& key,
                             const std::string& name = "key.json") {
    fs::create_directories(dir);
    const fs::path file = dir / name;
    const nlohmann::json j = {
        {"algorithm", "ed25519"},
        {"publicKey", encode_public_key_str(key.public_key)},
        {"privateSeed", util::base64_encode(key.seed.data(), key.seed.size())},
    };
    util::spit(file, std::string_view(j.dump(2) + "\n"));
#ifndef _WIN32
    std::error_code ec;
    fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ec);
#endif
    return file;
}

/// Generate a keypair and write it as a key file. Returns the file path.
inline fs::path make_keyfile(const fs::path& dir,
                             const std::string& name = "key.json") {
    return make_keyfile(dir, make_keypair(), name);
}

/// Parameters for the synthetic test application.
struct TestAppSpec {
    std::string id = "com.example.hello";
    std::string version = "1.0.0";
    /// Publisher key string for lexe.json; default is base64 of 32 zero
    /// bytes (structurally valid per FORMAT-0.1 §4, but unverifiable).
    std::string public_key =
        "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    /// entrypoint.executable (relative to payload/).
#ifdef _WIN32
    std::string entrypoint = "bin/hello.cmd";
#else
    std::string entrypoint = "bin/hello.sh";
#endif
    /// When non-empty, an `updates` block pointing here is added (§7).
    std::string update_url;
};

/// What make_test_app_tree produced.
struct TestAppTree {
    fs::path root;          // tree root
    fs::path payload_dir;   // root/payload  (contents become payload/)
    fs::path manifest_file; // root/lexe.json
    TestAppSpec spec;
};

/// Create an unpacked source tree for a tiny runnable app: a payload with
/// bin/hello.sh + bin/hello.cmd + data.txt, and a valid FORMAT-0.1 §5
/// lexe.json. Pack it with PackageWriter (or make_test_package below).
inline TestAppTree make_test_app_tree(const fs::path& root,
                                      const TestAppSpec& spec = {}) {
    TestAppTree tree;
    tree.root = root;
    tree.payload_dir = root / "payload";
    tree.manifest_file = root / "lexe.json";
    tree.spec = spec;

    util::spit(tree.payload_dir / "bin" / "hello.sh",
               std::string_view("#!/bin/sh\necho hello from " + spec.id +
                                "\nexit 0\n"));
    util::spit(tree.payload_dir / "bin" / "hello.cmd",
               std::string_view("@echo hello from " + spec.id +
                                "\r\n@exit /b 0\r\n"));
    util::spit(tree.payload_dir / "data.txt",
               std::string_view("test payload data for " + spec.id + "\n"));
#ifndef _WIN32
    std::error_code ec;
    fs::permissions(tree.payload_dir / "bin" / "hello.sh",
                    fs::perms::owner_all | fs::perms::group_read |
                        fs::perms::others_read,
                    ec);
#endif

    nlohmann::json manifest = {
        {"lexeVersion", "0.1"},
        {"id", spec.id},
        {"name", "Hello App"},
        {"version", spec.version},
        {"publisher",
         {{"name", "Test Publisher"}, {"publicKey", spec.public_key}}},
        {"applicationType", "native"},
        {"architectures", nlohmann::json::array({"x86_64", "aarch64"})},
        {"entrypoint",
         {{"executable", spec.entrypoint},
          {"arguments", nlohmann::json::array()}}},
        {"install", {{"scope", "user"}, {"mode", "bundled"}}},
    };
    if (!spec.update_url.empty()) {
        manifest["updates"] = {{"enabled", true},
                               {"channel", "stable"},
                               {"manifest", spec.update_url},
                               {"allowSourceChange", true}};
    }
    util::spit(tree.manifest_file, std::string_view(manifest.dump(2) + "\n"));
    return tree;
}

/// Build a fully signed `.lexe` from a fresh test tree using PackageWriter
/// (FORMAT-0.1 §1). spec.public_key is overwritten with `key`'s encoding so
/// the signatures verify. Returns the package path.
inline fs::path make_test_package(const fs::path& work_dir,
                                  const crypto::KeyPair& key,
                                  TestAppSpec spec = {}) {
    spec.public_key = encode_public_key_str(key.public_key);
    const TestAppTree tree =
        make_test_app_tree(work_dir / ("tree-" + spec.id + "-" + spec.version),
                           spec);
    PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path out = work_dir / (spec.id + "-" + spec.version + ".lexe");
    PackageWriter::write(inputs, key, out);
    return out;
}

/// Rewrite one entry of a ZIP archive in place: `mutate` receives the
/// entry's decompressed bytes and may change them arbitrarily (flip a byte,
/// truncate, replace). All other entries and their order are preserved.
/// Uses miniz directly (memory-backed, so paths never go through stdio).
/// Throws lexe::Error when the archive cannot be read or the entry does not
/// exist.
inline void tamper_entry(const fs::path& zip_path, const std::string& entry_name,
                         const std::function<void(std::vector<std::uint8_t>&)>& mutate) {
    struct EntryData {
        std::string name;
        std::vector<std::uint8_t> bytes;
    };
    std::vector<EntryData> entries;
    bool found = false;

    const std::vector<std::uint8_t> archive = util::slurp(zip_path);
    {
        mz_zip_archive zin;
        std::memset(&zin, 0, sizeof(zin));
        if (!mz_zip_reader_init_mem(&zin, archive.data(), archive.size(), 0)) {
            throw Error("tamper_entry: cannot open archive: " +
                        zip_path.string());
        }
        const mz_uint count = mz_zip_reader_get_num_files(&zin);
        for (mz_uint i = 0; i < count; ++i) {
            mz_zip_archive_file_stat st;
            std::memset(&st, 0, sizeof(st));
            if (!mz_zip_reader_file_stat(&zin, i, &st)) {
                mz_zip_reader_end(&zin);
                throw Error("tamper_entry: cannot stat entry");
            }
            if (mz_zip_reader_is_file_a_directory(&zin, i)) continue;
            EntryData e;
            e.name = st.m_filename;
            if (st.m_uncomp_size > 0) {
                std::size_t size = 0;
                void* p = mz_zip_reader_extract_to_heap(&zin, i, &size, 0);
                if (p == nullptr) {
                    mz_zip_reader_end(&zin);
                    throw Error("tamper_entry: cannot extract entry");
                }
                e.bytes.assign(static_cast<std::uint8_t*>(p),
                               static_cast<std::uint8_t*>(p) + size);
                mz_free(p);
            }
            if (e.name == entry_name) {
                mutate(e.bytes);
                found = true;
            }
            entries.push_back(std::move(e));
        }
        mz_zip_reader_end(&zin);
    }

    if (!found) {
        throw Error("tamper_entry: no such entry: " + entry_name);
    }

    mz_zip_archive zout;
    std::memset(&zout, 0, sizeof(zout));
    if (!mz_zip_writer_init_heap(&zout, 0, 0)) {
        throw Error("tamper_entry: cannot create archive");
    }
    for (const auto& e : entries) {
        const void* data = e.bytes.empty()
                               ? static_cast<const void*>("")
                               : static_cast<const void*>(e.bytes.data());
        // Same store/deflate rule as PackageWriter (FORMAT-0.1 §1) so a
        // tampered archive stays structurally spec-shaped.
        const mz_uint level = e.bytes.size() < 64
                                  ? static_cast<mz_uint>(MZ_NO_COMPRESSION)
                                  : static_cast<mz_uint>(MZ_BEST_COMPRESSION);
        if (!mz_zip_writer_add_mem(&zout, e.name.c_str(), data, e.bytes.size(),
                                   level)) {
            mz_zip_writer_end(&zout);
            throw Error("tamper_entry: cannot add entry: " + e.name);
        }
    }
    void* buf = nullptr;
    std::size_t size = 0;
    if (!mz_zip_writer_finalize_heap_archive(&zout, &buf, &size)) {
        mz_zip_writer_end(&zout);
        throw Error("tamper_entry: cannot finalize archive");
    }
    try {
        util::spit(zip_path, static_cast<const std::uint8_t*>(buf), size);
    } catch (...) {
        mz_zip_writer_end(&zout);
        throw;
    }
    mz_zip_writer_end(&zout);
}

} // namespace lexe::test

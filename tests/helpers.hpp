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

#include "elf_builder.hpp"

#include "core/crypto.hpp"
#include "core/elf.hpp"
#include "core/error.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"

#include <ed25519/ed25519.h>
#include <miniz/miniz.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
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

// --------------------------------------------------------- native executable
// FORMAT-0.1 §5 / Definitive Architecture §14.2: a package that declares
// applicationType "native" must ship a COMPILED executable as its entrypoint —
// the verify pipeline's "payload-role" stage rejects scripts and source text.
// Test payloads therefore need a REAL native executable, not a shell script.
//
// write_native_executable compiles a tiny C program with the host toolchain
// (cc, then gcc, then clang) and copies the result to `dest`. The program
// prints `stdout_text` followed by a newline, then one "arg: <value>" line per
// argument, then exits with `exit_code` — enough for the launcher/e2e tests to
// assert on stdout, arguments and exit status.
//
// Compiles are cached process-wide, keyed by the exact generated source, so the
// hundreds of packages this suite builds pay for at most a handful of compiler
// invocations. On a host with no usable C compiler it falls back to a
// synthesized ELF image (elf_builder.hpp) that is structurally a real
// executable for the host architecture: verification-only tests still pass, but
// the file cannot be run — tests that EXECUTE the app must guard on
// have_native_compiler().

namespace native_exe_detail {

/// The host's ELF e_machine, so the compiler-less fallback still satisfies the
/// manifest's declared architectures.
inline std::uint16_t host_elf_machine() {
#if defined(__aarch64__)
    return 183; // EM_AARCH64
#elif defined(__arm__)
    return 40; // EM_ARM
#elif defined(__riscv)
    return 243; // EM_RISCV
#elif defined(__powerpc64__)
    return 21; // EM_PPC64
#elif defined(__s390x__)
    return 22; // EM_S390
#elif defined(__i386__)
    return 3; // EM_386
#else
    return 62; // EM_X86_64
#endif
}

/// `text` as a C string literal. Non-printables become three-digit octal
/// escapes (never \x, which would swallow following hex digits); '?' is
/// escaped so no trigraph can form.
inline std::string c_string_literal(const std::string& text) {
    std::string out = "\"";
    for (const unsigned char c : text) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '?': out += "\\?"; break;
        default:
            if (c < 0x20 || c >= 0x7f) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\%03o",
                              static_cast<unsigned>(c));
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += "\"";
    return out;
}

/// The C program for one (stdout_text, exit_code) pair. Also the cache key, so
/// it must be byte-identical for identical parameters.
inline std::string make_source(const std::string& stdout_text, int exit_code) {
    return "#include <stdio.h>\n"
           "int main(int argc, char** argv) {\n"
           "    int i;\n"
           "    fputs(" +
           c_string_literal(stdout_text + "\n") +
           ", stdout);\n"
           "    for (i = 1; i < argc; ++i) {\n"
           "        printf(\"arg: %s\\n\", argv[i]);\n"
           "    }\n"
           "    fflush(stdout);\n"
           "    return " +
           std::to_string(exit_code) +
           ";\n"
           "}\n";
}

/// Process-wide compile cache. The temp directory is removed at exit; the
/// copies handed to callers are independent files and survive it.
struct Cache {
    std::mutex mutex;
    std::filesystem::path dir;
    std::map<std::string, std::filesystem::path> by_source;
    std::string compiler;                 // resolved compiler name, "" = unknown
    std::optional<bool> compiler_works;   // set on the first compile attempt

    ~Cache() {
        std::error_code ec;
        if (!dir.empty()) std::filesystem::remove_all(dir, ec);
    }
};

inline Cache& cache() {
    static Cache c;
    return c;
}

/// Compile `source` to `out` with the first working host compiler. Returns
/// false when no compiler is usable or the output is not a runnable ELF object
/// (e.g. a cross/PE toolchain), which sends the caller to the ELF fallback.
inline bool compile_source(Cache& c, const std::string& source,
                           const std::filesystem::path& out) {
    if (c.compiler_works.has_value() && !*c.compiler_works) return false;

    const std::filesystem::path src = out.parent_path() /
                                      (out.stem().string() + ".c");
    util::spit(src, std::string_view(source));

    std::vector<std::string> candidates;
    if (!c.compiler.empty()) {
        candidates.push_back(c.compiler);
    } else {
        candidates = {"cc", "gcc", "clang"};
    }

    bool ok = false;
    for (const std::string& candidate : candidates) {
        try {
            const util::ProcessResult r = util::run_process(
                {candidate, "-O0", "-w", "-o", out.string(), src.string()});
            if (r.exit_code != 0) continue;
        } catch (const std::exception&) {
            continue; // not on PATH
        }
        const elf::ElfInfo info = elf::read(out);
        if (!info.is_elf || (info.type != elf::Type::Executable &&
                             info.type != elf::Type::SharedObject)) {
            continue;
        }
        c.compiler = candidate;
        ok = true;
        break;
    }

    std::error_code ec;
    std::filesystem::remove(src, ec);
    c.compiler_works = ok;
    return ok;
}

/// Build (or reuse) the executable for `source`. Caller holds c.mutex. When
/// `allow_fallback` is false and no compiler is usable, returns an empty path
/// and writes nothing.
inline std::filesystem::path build_locked(Cache& c, const std::string& source,
                                          bool allow_fallback = true) {
    const auto it = c.by_source.find(source);
    if (it != c.by_source.end()) return it->second;

    if (c.dir.empty()) {
        c.dir = unique_temp_dir("lexe-test-native-");
        std::filesystem::create_directories(c.dir);
    }
    const std::string stem = "exe" + std::to_string(c.by_source.size());
#ifdef _WIN32
    const std::filesystem::path out = c.dir / (stem + ".exe");
#else
    const std::filesystem::path out = c.dir / stem;
#endif
    if (!compile_source(c, source, out)) {
        if (!allow_fallback) return {};
        // No usable compiler: synthesize a structurally valid ELF executable
        // for the host architecture. Real enough for the payload-role stage,
        // not runnable — see have_native_compiler().
        ElfSpec spec;
        spec.e_type = 2; // ET_EXEC
        spec.e_machine = host_elf_machine();
        write_elf(out, spec);
    }
    c.by_source.emplace(source, out);
    return out;
}

/// Copy a built binary to `dest` and make it executable.
inline void install_executable(const std::filesystem::path& built,
                               const std::filesystem::path& dest) {
    if (dest.has_parent_path()) {
        std::filesystem::create_directories(dest.parent_path());
    }
    std::filesystem::copy_file(built, dest,
                               std::filesystem::copy_options::overwrite_existing);
#ifndef _WIN32
    std::error_code ec;
    std::filesystem::permissions(
        dest,
        std::filesystem::perms::owner_all |
            std::filesystem::perms::group_read |
            std::filesystem::perms::group_exec |
            std::filesystem::perms::others_read |
            std::filesystem::perms::others_exec,
        std::filesystem::perm_options::replace, ec);
#endif
}

} // namespace native_exe_detail

/// Whether this host can build a RUNNABLE native test executable. Tests that
/// actually execute the packaged app should skip when this is false; tests that
/// only verify/install packages do not need to care.
inline bool have_native_compiler() {
    auto& c = native_exe_detail::cache();
    std::lock_guard<std::mutex> lock(c.mutex);
    native_exe_detail::build_locked(
        c, native_exe_detail::make_source("lexe native compiler probe", 0));
    return c.compiler_works.value_or(false);
}

/// Compile `c_source` into `dest` with the host toolchain (cached exactly like
/// write_native_executable). Returns false — writing nothing — when there is
/// no usable compiler; a test that needs a RUNNABLE payload of its own shape
/// should skip in that case. Use this when the fixed shape of
/// write_native_executable's program is not enough.
inline bool compile_native_executable(const fs::path& dest,
                                      const std::string& c_source) {
    if (!have_native_compiler()) return false;
    fs::path built;
    {
        auto& c = native_exe_detail::cache();
        std::lock_guard<std::mutex> lock(c.mutex);
        built = native_exe_detail::build_locked(c, c_source,
                                                /*allow_fallback=*/false);
    }
    if (built.empty()) return false;
    native_exe_detail::install_executable(built, dest);
    return true;
}

/// Write a real native executable to `dest`: prints `stdout_text` + "\n", then
/// "arg: <value>" for each argument, then exits with `exit_code`.
inline void write_native_executable(const fs::path& dest,
                                    const std::string& stdout_text,
                                    int exit_code = 0) {
    const std::string source =
        native_exe_detail::make_source(stdout_text, exit_code);

    fs::path built;
    {
        auto& c = native_exe_detail::cache();
        std::lock_guard<std::mutex> lock(c.mutex);
        built = native_exe_detail::build_locked(c, source);
    }
    native_exe_detail::install_executable(built, dest);
}

/// e_machine for a FORMAT-0.1 §5 architecture id.
inline std::uint16_t elf_machine_for_arch(const std::string& arch) {
    if (arch == "aarch64") return 183; // EM_AARCH64
    if (arch == "riscv64") return 243; // EM_RISCV
    return 62;                         // EM_X86_64
}

/// Write a synthesized ELF *executable* for `arch`. Structurally a real ELF —
/// enough for the verify pipeline's "payload-role" stage — but NOT runnable.
/// Use it when the test needs an entrypoint for an architecture the host
/// cannot compile for (e.g. the compatibility-stage fixtures).
inline void write_elf_executable_for_arch(const fs::path& dest,
                                          const std::string& arch) {
    ElfSpec spec;
    spec.e_type = 2; // ET_EXEC
    spec.e_machine = elf_machine_for_arch(arch);
    if (dest.has_parent_path()) fs::create_directories(dest.parent_path());
    write_elf(dest, spec);
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
    std::string entrypoint = "bin/hello.exe";
#else
    std::string entrypoint = "bin/hello";
#endif
    /// FORMAT-0.1 §5 architectures. The entrypoint written into the payload is
    /// a real ELF for one of them: a COMPILED host binary when the host
    /// architecture is listed, otherwise a synthesized (non-runnable) ELF for
    /// architectures.front().
    std::vector<std::string> architectures = {"x86_64", "aarch64"};
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

/// Create an unpacked source tree for a tiny runnable app: a payload with a
/// compiled native entrypoint (bin/hello, bin/hello.exe on Windows) plus
/// bin/hello.sh + bin/hello.cmd + data.txt as ordinary payload files, and a
/// valid FORMAT-0.1 §5 lexe.json. Pack it with PackageWriter (or
/// make_test_package below).
inline TestAppTree make_test_app_tree(const fs::path& root,
                                      const TestAppSpec& spec = {}) {
    TestAppTree tree;
    tree.root = root;
    tree.payload_dir = root / "payload";
    tree.manifest_file = root / "lexe.json";
    tree.spec = spec;

    // The real entrypoint: a compiled native executable, because
    // applicationType "native" is verified against the payload's actual bytes
    // (verify.cpp "payload-role"). bin/hello.sh / bin/hello.cmd stay below as
    // ORDINARY payload files — repair/corruption tests assert on their exact
    // contents.
#ifdef _WIN32
    const fs::path native_entry = tree.payload_dir / "bin" / "hello.exe";
#else
    const fs::path native_entry = tree.payload_dir / "bin" / "hello";
#endif
    if (std::find(spec.architectures.begin(), spec.architectures.end(),
                  host_architecture()) != spec.architectures.end()) {
        write_native_executable(native_entry, "hello from " + spec.id, 0);
    } else {
        // The package targets an architecture this host cannot compile for
        // (compatibility-stage fixtures): synthesize an ELF for it instead.
        write_elf_executable_for_arch(native_entry,
                                      spec.architectures.empty()
                                          ? std::string("x86_64")
                                          : spec.architectures.front());
    }

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
        {"architectures", spec.architectures},
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

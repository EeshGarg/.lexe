// package — PackageReader / PackageWriter implementation.
// FORMAT-0.1 §1 (deterministic container), §2 (entry rules), §3 (hashes.json),
// §4 (signatures). SHA-256 and Ed25519 are performed through the vendored
// primitives (PicoSHA2, orlp/ed25519) directly — the same backends the crypto
// module wraps — so packaging is self-contained and byte-compatible with
// lexe::crypto regardless of module landing order.

#include "core/package.hpp"
#include "core/error.hpp"
#include "core/util.hpp"

#include <ed25519/ed25519.h>
#include <miniz/miniz.h>
#include <nlohmann/json.hpp>
#include <picosha2/picosha2.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <utility>

namespace fs = std::filesystem;

namespace lexe {

namespace {

// ------------------------------------------------------------------ paths

bool is_ascii_alpha(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

std::vector<std::string> split_segments(const std::string& path) {
    std::vector<std::string> segments;
    std::size_t start = 0;
    while (true) {
        const std::size_t slash = path.find('/', start);
        if (slash == std::string::npos) {
            segments.push_back(path.substr(start));
            break;
        }
        segments.push_back(path.substr(start, slash - start));
        start = slash + 1;
    }
    return segments;
}

/// Human-readable rendering of an entry path (NUL bytes made visible).
std::string printable(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (const char c : raw) {
        if (c == '\0') {
            out += "<NUL>";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

/// FORMAT-0.1 §2 entry-path rules. Returns the reason a path must be
/// rejected, or nullopt when the path is acceptable. Applied to every entry
/// (including directory entries, whose trailing '/' is stripped first).
std::optional<std::string> entry_path_problem(const std::string& raw) {
    if (raw.empty()) return "empty entry path";
    if (raw.find('\0') != std::string::npos) return "path contains a NUL byte";
    if (raw.find('\\') != std::string::npos) return "path contains a backslash";
    if (raw.front() == '/') return "absolute path";

    std::string path = raw;
    const bool is_directory = path.back() == '/';
    if (is_directory) path.pop_back();
    if (path.empty()) return "empty entry path";

    const std::vector<std::string> segments = split_segments(path);
    for (const std::string& seg : segments) {
        if (seg.empty()) return "empty path segment";
        if (seg == "..") return "'..' path segment";
        if (seg == ".") return "'.' path segment";
        if (seg.size() >= 2 && is_ascii_alpha(seg[0]) && seg[1] == ':') {
            return "Windows drive designator";
        }
    }

    static constexpr std::string_view kAllowedTopLevel[] = {
        "icons", "lexe.json", "metadata", "payload", "scripts", "signatures"};
    const std::string& first = segments.front();
    const bool allowed =
        std::find(std::begin(kAllowedTopLevel), std::end(kAllowedTopLevel),
                  first) != std::end(kAllowedTopLevel);
    if (!allowed) {
        return "first path segment '" + first +
               "' is not an allowed top-level name";
    }
    if (first == "lexe.json" && (is_directory || segments.size() > 1)) {
        return "'lexe.json' must be a top-level file";
    }
    return std::nullopt;
}

/// Convert a validated UTF-8 entry path segment to a filesystem path
/// (on Windows fs::path(std::string) would decode via the ANSI codepage).
fs::path utf8_segment_to_path(const std::string& segment) {
#ifdef _WIN32
    return fs::path(std::u8string(segment.begin(), segment.end()));
#else
    return fs::path(segment);
#endif
}

/// Exact raw entry name bytes (embedded NUL preserved — m_filename would
/// truncate at the first NUL, hiding a FORMAT §2 violation).
std::string raw_entry_name(mz_zip_archive& zip, mz_uint index) {
    const mz_uint needed = mz_zip_reader_get_filename(&zip, index, nullptr, 0);
    if (needed <= 1) return std::string();
    std::vector<char> buf(needed);
    mz_zip_reader_get_filename(&zip, index, buf.data(), needed);
    return std::string(buf.data(), needed - 1);
}

// ------------------------------------------------------------------ crypto

/// SHA-256 lowercase hex (FORMAT-0.1 §3) via vendored PicoSHA2.
std::string sha256_hex_of(const std::vector<std::uint8_t>& bytes) {
    std::array<unsigned char, picosha2::k_digest_size> digest{};
    picosha2::hash256(bytes.begin(), bytes.end(), digest.begin(),
                      digest.end());
    return util::hex_encode(digest.data(), digest.size());
}

/// Raw 64-byte Ed25519 signature over exact bytes (FORMAT-0.1 §4). The pair
/// is re-derived from the seed on every use, per §4 "Key files".
crypto::Signature sign_bytes(const std::vector<std::uint8_t>& message,
                             const crypto::Seed& seed) {
    std::array<unsigned char, 32> pub{};
    std::array<unsigned char, 64> priv{};
    ed25519_create_keypair(pub.data(), priv.data(), seed.data());
    crypto::Signature sig{};
    static const unsigned char kEmpty = 0;
    ed25519_sign(sig.data(), message.empty() ? &kEmpty : message.data(),
                 message.size(), pub.data(), priv.data());
    return sig;
}

} // namespace

// =================================================================== Reader

struct PackageReader::Impl {
    struct File {
        PackageEntry entry;
        mz_uint index = 0;
        mz_uint32 ext_attr = 0;
    };

    fs::path file;
    std::vector<std::uint8_t> bytes; // archive bytes (mem-backed reader)
    mz_zip_archive zip{};
    bool open = false;
    std::vector<File> files;                   // sorted by entry.path
    std::map<std::string, std::size_t> lookup; // path -> position in files

    ~Impl() {
        if (open) mz_zip_reader_end(&zip);
    }
};

PackageReader::PackageReader(const fs::path& lexe_file)
    : impl_(std::make_unique<Impl>()) {
    impl_->file = lexe_file;
    impl_->bytes = util::slurp(lexe_file); // NotFoundError when missing
    if (!mz_zip_reader_init_mem(&impl_->zip, impl_->bytes.data(),
                                impl_->bytes.size(), 0)) {
        throw VerificationError("package: not a valid ZIP archive: " +
                                lexe_file.string());
    }
    impl_->open = true;

    // FORMAT-0.1 §2 — validate every entry before anything is trusted.
    std::set<std::string> seen;
    const mz_uint count = mz_zip_reader_get_num_files(&impl_->zip);
    for (mz_uint i = 0; i < count; ++i) {
        const std::string name = raw_entry_name(impl_->zip, i);
        if (const auto problem = entry_path_problem(name)) {
            throw VerificationError("package: rejected entry '" +
                                    printable(name) + "': " + *problem);
        }
        mz_zip_archive_file_stat st;
        std::memset(&st, 0, sizeof(st));
        if (!mz_zip_reader_file_stat(&impl_->zip, i, &st)) {
            throw VerificationError("package: cannot read entry record #" +
                                    std::to_string(i));
        }
        // Symbolic link entries (ZIP external attributes: Unix mode S_IFLNK).
        if (((st.m_external_attr >> 16) & 0xF000u) == 0xA000u) {
            throw VerificationError("package: rejected entry '" + name +
                                    "': symbolic link");
        }
        if (st.m_is_encrypted || !st.m_is_supported) {
            throw VerificationError("package: rejected entry '" + name +
                                    "': encrypted or unsupported");
        }
        if (!seen.insert(name).second) {
            throw VerificationError("package: duplicate entry path: " + name);
        }
        if (mz_zip_reader_is_file_a_directory(&impl_->zip, i)) continue;

        Impl::File f;
        f.entry.path = name;
        f.entry.uncompressed_size = st.m_uncomp_size;
        f.index = i;
        f.ext_attr = st.m_external_attr;
        impl_->files.push_back(std::move(f));
    }

    std::sort(impl_->files.begin(), impl_->files.end(),
              [](const Impl::File& a, const Impl::File& b) {
                  return a.entry.path < b.entry.path;
              });
    for (std::size_t i = 0; i < impl_->files.size(); ++i) {
        impl_->lookup.emplace(impl_->files[i].entry.path, i);
    }

    // Required entries (FORMAT-0.1 §2). 0.1 supports only bundled mode, so
    // payload/ content is required as well.
    static constexpr std::string_view kRequired[] = {
        "lexe.json", "metadata/hashes.json", "signatures/manifest.sig",
        "signatures/payload.sig"};
    for (const std::string_view required : kRequired) {
        if (impl_->lookup.find(std::string(required)) == impl_->lookup.end()) {
            throw VerificationError("package: required entry missing: " +
                                    std::string(required));
        }
    }
    const bool has_payload = std::any_of(
        impl_->files.begin(), impl_->files.end(), [](const Impl::File& f) {
            return f.entry.path.rfind("payload/", 0) == 0 &&
                   f.entry.path.size() > 8;
        });
    if (!has_payload) {
        throw VerificationError(
            "package: required payload/ entries missing (bundled mode)");
    }
}

PackageReader::~PackageReader() = default;
PackageReader::PackageReader(PackageReader&&) noexcept = default;
PackageReader& PackageReader::operator=(PackageReader&&) noexcept = default;

const fs::path& PackageReader::file() const { return impl_->file; }

std::vector<PackageEntry> PackageReader::entries() const {
    std::vector<PackageEntry> out;
    out.reserve(impl_->files.size());
    for (const Impl::File& f : impl_->files) out.push_back(f.entry);
    return out;
}

bool PackageReader::has_entry(const std::string& entry_path) const {
    return impl_->lookup.find(entry_path) != impl_->lookup.end();
}

std::vector<std::uint8_t>
PackageReader::read_entry(const std::string& entry_path) const {
    const auto it = impl_->lookup.find(entry_path);
    if (it == impl_->lookup.end()) {
        throw NotFoundError("package: no such entry: " + entry_path);
    }
    const Impl::File& f = impl_->files[it->second];
    if (f.entry.uncompressed_size == 0) return {};
    std::size_t size = 0;
    void* p = mz_zip_reader_extract_to_heap(&impl_->zip, f.index, &size, 0);
    if (p == nullptr) {
        throw VerificationError("package: cannot extract entry (corrupt?): " +
                                entry_path);
    }
    std::vector<std::uint8_t> out(static_cast<std::uint8_t*>(p),
                                  static_cast<std::uint8_t*>(p) + size);
    mz_free(p);
    return out;
}

void PackageReader::extract_payload(const fs::path& dest_dir) const {
    fs::create_directories(dest_dir);
    const fs::path root = fs::weakly_canonical(dest_dir);
    constexpr std::string_view kPrefix = "payload/";

    for (const Impl::File& f : impl_->files) {
        const std::string& path = f.entry.path;
        if (path.size() <= kPrefix.size() ||
            path.compare(0, kPrefix.size(), kPrefix) != 0) {
            continue;
        }
        const std::string rel = path.substr(kPrefix.size());

        fs::path out = root;
        for (const std::string& seg : split_segments(rel)) {
            out /= utf8_segment_to_path(seg);
        }

        // Security invariant #1: the resolved destination must remain under
        // the target root (defense in depth on top of the §2 name rules).
        const fs::path resolved = fs::weakly_canonical(out);
        const fs::path relative = resolved.lexically_relative(root);
        if (relative.empty() || relative == fs::path(".") ||
            relative.begin()->string() == "..") {
            throw VerificationError(
                "package: entry escapes extraction root: " + path);
        }

        fs::create_directories(resolved.parent_path());
        util::spit(resolved, read_entry(path));

#ifndef _WIN32
        // Preserve executable bits carried in Unix external attributes.
        const mz_uint32 mode = f.ext_attr >> 16;
        if ((mode & 0111u) != 0) {
            fs::perms add = fs::perms::none;
            if ((mode & 0100u) != 0) add |= fs::perms::owner_exec;
            if ((mode & 0010u) != 0) add |= fs::perms::group_exec;
            if ((mode & 0001u) != 0) add |= fs::perms::others_exec;
            std::error_code ec;
            fs::permissions(resolved, add, fs::perm_options::add, ec);
        }
#endif
    }
}

// =================================================================== Writer

namespace {

// FORMAT-0.1 §1/§D: entries record a normalized Unix mode in the ZIP external
// attributes — 0755 for files executable in the source tree, 0644 otherwise.
// Only these two canonical modes are ever recorded (no umask leakage, no
// special bits), so packing stays deterministic.
constexpr mz_uint32 kModeExec = 0755;
constexpr mz_uint32 kModeData = 0644;

struct WriteEntry {
    std::string path;
    std::vector<std::uint8_t> bytes;
    mz_uint32 mode = kModeData; // generated entries default to 0644
};

/// Recursively collect regular files of `dir` as entries `prefix + relpath`,
/// recording each file's executability. On POSIX the owner-exec bit is
/// authoritative; Windows has no Unix exec bit, so files pack as 0644 there
/// (a package's helper executables must be produced on a POSIX filesystem).
void collect_tree(const fs::path& dir, const std::string& prefix,
                  std::vector<WriteEntry>& out) {
    for (fs::recursive_directory_iterator it(dir), end; it != end; ++it) {
        if (fs::is_symlink(it->symlink_status())) {
            throw Error("pack: symbolic links are not supported in package "
                        "sources: " +
                        it->path().string());
        }
        if (it->is_directory()) continue;
        if (!it->is_regular_file()) {
            throw Error("pack: not a regular file: " + it->path().string());
        }
        // Exact UTF-8 bytes of the relative path, '/'-separated.
        const std::u8string rel8 =
            it->path().lexically_relative(dir).generic_u8string();
        const std::string entry_path =
            prefix + std::string(rel8.begin(), rel8.end());
        if (const auto problem = entry_path_problem(entry_path)) {
            throw Error("pack: invalid entry path '" + printable(entry_path) +
                        "': " + *problem);
        }
        mz_uint32 mode = kModeData;
#ifndef _WIN32
        std::error_code ec;
        if ((it->status(ec).permissions() & fs::perms::owner_exec) !=
            fs::perms::none) {
            mode = kModeExec;
        }
#endif
        out.push_back({entry_path, util::slurp(it->path()), mode});
    }
}

/// Rewrite each central-directory record's external attributes to carry the
/// entry's Unix mode (miniz's add-from-memory path hardcodes ext_attr = 0), and
/// mark "version made by" as Unix so both PackageReader and `unzip` restore the
/// modes. Operates on miniz's finalized output — the vendored library is not
/// modified. Deterministic: the patched bytes are a pure function of the modes.
void patch_central_directory_modes(std::vector<std::uint8_t>& zip,
                                   const std::vector<WriteEntry>& entries) {
    auto rd16 = [&](std::size_t o) -> mz_uint32 {
        return static_cast<mz_uint32>(zip[o]) |
               (static_cast<mz_uint32>(zip[o + 1]) << 8);
    };
    auto rd32 = [&](std::size_t o) -> mz_uint32 {
        return static_cast<mz_uint32>(zip[o]) |
               (static_cast<mz_uint32>(zip[o + 1]) << 8) |
               (static_cast<mz_uint32>(zip[o + 2]) << 16) |
               (static_cast<mz_uint32>(zip[o + 3]) << 24);
    };
    constexpr mz_uint32 kEocdSig = 0x06054b50u;
    constexpr mz_uint32 kCdSig = 0x02014b50u;

    if (zip.size() < 22) return;
    // No ZIP comment is ever written, so the EOCD is the final 22 bytes; scan
    // back defensively in case that ever changes.
    std::size_t eocd = zip.size() - 22;
    while (rd32(eocd) != kEocdSig) {
        if (eocd == 0) return; // no EOCD found; leave the archive as miniz built it
        --eocd;
    }
    const mz_uint32 count = rd16(eocd + 10);
    std::size_t off = rd32(eocd + 16);

    std::map<std::string, mz_uint32> modes;
    for (const WriteEntry& e : entries) modes[e.path] = e.mode;

    for (mz_uint32 i = 0; i < count; ++i) {
        if (off + 46 > zip.size() || rd32(off) != kCdSig) return;
        const mz_uint32 fnlen = rd16(off + 28);
        const mz_uint32 extralen = rd16(off + 30);
        const mz_uint32 commentlen = rd16(off + 32);
        if (off + 46 + fnlen > zip.size()) return;
        const std::string name(reinterpret_cast<const char*>(&zip[off + 46]),
                               fnlen);
        const auto found = modes.find(name);
        if (found != modes.end()) {
            const mz_uint32 ext = found->second << 16; // Unix mode in high word
            zip[off + 38] = static_cast<std::uint8_t>(ext & 0xFF);
            zip[off + 39] = static_cast<std::uint8_t>((ext >> 8) & 0xFF);
            zip[off + 40] = static_cast<std::uint8_t>((ext >> 16) & 0xFF);
            zip[off + 41] = static_cast<std::uint8_t>((ext >> 24) & 0xFF);
            zip[off + 5] = 3; // "version made by" host = Unix (3)
        }
        off += 46u + fnlen + extralen + commentlen;
    }
}

struct ZipWriterGuard {
    mz_zip_archive* zip;
    ~ZipWriterGuard() { mz_zip_writer_end(zip); }
};

} // namespace

void PackageWriter::write(const Inputs& inputs, const crypto::KeyPair& key,
                          const fs::path& out_lexe) {
    if (inputs.payload_dir.empty() || !fs::is_directory(inputs.payload_dir)) {
        throw Error("pack: payload directory not found: " +
                    inputs.payload_dir.string());
    }
    if (inputs.manifest_file.empty() ||
        !fs::is_regular_file(inputs.manifest_file)) {
        throw Error("pack: manifest file not found: " +
                    inputs.manifest_file.string());
    }

    std::vector<WriteEntry> entries;

    // lexe.json — stored verbatim; the signature covers these exact bytes.
    // Full §5 validation is the manifest module's concern (the CLI runs it);
    // here we only require well-formed JSON so a broken file cannot ship.
    std::vector<std::uint8_t> manifest_bytes =
        util::slurp(inputs.manifest_file);
    {
        const nlohmann::json parsed = nlohmann::json::parse(
            manifest_bytes.begin(), manifest_bytes.end(), nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object()) {
            throw Error("pack: manifest is not a valid JSON object: " +
                        inputs.manifest_file.string());
        }
    }
    entries.push_back({"lexe.json", manifest_bytes});

    const std::size_t before_payload = entries.size();
    collect_tree(inputs.payload_dir, "payload/", entries);
    if (entries.size() == before_payload) {
        throw Error("pack: payload directory contains no files: " +
                    inputs.payload_dir.string());
    }

    if (inputs.icons_dir.has_value()) {
        if (!fs::is_directory(*inputs.icons_dir)) {
            throw Error("pack: icons directory not found: " +
                        inputs.icons_dir->string());
        }
        collect_tree(*inputs.icons_dir, "icons/", entries);
    }
    if (inputs.metadata_dir.has_value()) {
        if (!fs::is_directory(*inputs.metadata_dir)) {
            throw Error("pack: metadata directory not found: " +
                        inputs.metadata_dir->string());
        }
        const std::size_t first = entries.size();
        collect_tree(*inputs.metadata_dir, "metadata/", entries);
        for (std::size_t i = first; i < entries.size(); ++i) {
            if (entries[i].path == "metadata/hashes.json") {
                throw Error("pack: metadata/hashes.json is generated and "
                            "must not exist in the metadata directory");
            }
        }
    }

    // FORMAT-0.1 §3 — metadata/hashes.json covers every entry except
    // lexe.json, itself, and signatures/* (none of which exist yet).
    nlohmann::json files = nlohmann::json::object();
    for (const WriteEntry& e : entries) {
        if (e.path == "lexe.json") continue;
        files[e.path] = sha256_hex_of(e.bytes);
    }
    const nlohmann::json hashes = {{"algorithm", "sha256"},
                                   {"files", files}};
    const std::string hashes_text = hashes.dump(2);
    std::vector<std::uint8_t> hashes_bytes(hashes_text.begin(),
                                           hashes_text.end());

    // FORMAT-0.1 §4 — raw 64-byte Ed25519 signatures over the exact stored
    // bytes of lexe.json and metadata/hashes.json.
    const crypto::Signature manifest_sig = sign_bytes(manifest_bytes, key.seed);
    const crypto::Signature payload_sig = sign_bytes(hashes_bytes, key.seed);
    entries.push_back({"metadata/hashes.json", std::move(hashes_bytes)});
    entries.push_back(
        {"signatures/manifest.sig",
         std::vector<std::uint8_t>(manifest_sig.begin(), manifest_sig.end())});
    entries.push_back(
        {"signatures/payload.sig",
         std::vector<std::uint8_t>(payload_sig.begin(), payload_sig.end())});

    // FORMAT-0.1 §1 — lexicographic byte order (std::string compares as
    // unsigned bytes, memcmp semantics); duplicates are a hard error.
    std::sort(entries.begin(), entries.end(),
              [](const WriteEntry& a, const WriteEntry& b) {
                  return a.path < b.path;
              });
    for (std::size_t i = 1; i < entries.size(); ++i) {
        if (entries[i].path == entries[i - 1].path) {
            throw Error("pack: duplicate entry path: " + entries[i].path);
        }
    }

    // Deterministic write: zeroed timestamps (MINIZ_NO_TIME), DEFLATE 9, or
    // STORE for entries smaller than 64 bytes; no ZIP64 unless required, no
    // encryption, no comments, no extra fields.
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    if (!mz_zip_writer_init_heap(&zip, 0, 0)) {
        throw Error("pack: cannot initialize ZIP writer");
    }
    ZipWriterGuard guard{&zip};
    for (const WriteEntry& e : entries) {
        const mz_uint level = e.bytes.size() < 64
                                  ? static_cast<mz_uint>(MZ_NO_COMPRESSION)
                                  : static_cast<mz_uint>(MZ_BEST_COMPRESSION);
        const void* data = e.bytes.empty()
                               ? static_cast<const void*>("")
                               : static_cast<const void*>(e.bytes.data());
        if (!mz_zip_writer_add_mem(&zip, e.path.c_str(), data, e.bytes.size(),
                                   level)) {
            throw Error("pack: cannot add entry: " + e.path);
        }
    }
    void* buf = nullptr;
    std::size_t buf_size = 0;
    if (!mz_zip_writer_finalize_heap_archive(&zip, &buf, &buf_size)) {
        throw Error("pack: cannot finalize archive");
    }
    // Copy out of miniz's heap buffer, then stamp the Unix modes into the
    // central directory (FORMAT-0.1 §1/§D) before writing to disk.
    std::vector<std::uint8_t> archive(
        static_cast<const std::uint8_t*>(buf),
        static_cast<const std::uint8_t*>(buf) + buf_size);
    // guard's mz_zip_writer_end frees buf.
    patch_central_directory_modes(archive, entries);
    util::spit(out_lexe, archive);
}

} // namespace lexe

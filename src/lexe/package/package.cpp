// package — PackageReader / PackageWriter implementation.
// FORMAT-0.1 §1 (deterministic container), §2 (entry rules), §3 (hashes.json),
// §4 (signatures). SHA-256 and Ed25519 are performed through the vendored
// primitives (PicoSHA2, orlp/ed25519) directly — the same backends the crypto
// module wraps — so packaging is self-contained and byte-compatible with
// lexe::crypto regardless of module landing order.

#include "lexe/package/package.hpp"
#include "lexe/base/error.hpp"
#include "lexe/base/json_strict.hpp"
#include "lexe/base/limits.hpp"
#include "lexe/base/util.hpp"

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

/// The bare top-level `role` string of a `lexe.json`, WITHOUT validating the
/// manifest (Definitive Architecture §15.1). Structure rules differ by role,
/// and structure is checked before the manifest module ever runs, so the
/// reader needs this one hint. Anything unreadable/absent reads as
/// "application" — the stricter of the two rule sets.
std::string declared_role(const std::vector<std::uint8_t>& lexe_json_bytes) {
    try {
        const nlohmann::json doc = json_strict::parse(
            std::string_view(
                reinterpret_cast<const char*>(lexe_json_bytes.data()),
                lexe_json_bytes.size()),
            "manifest", limits::kMaxManifestBytes);
        if (!doc.is_object()) return "application";
        const auto it = doc.find("role");
        if (it == doc.end() || !it->is_string()) return "application";
        return it->get<std::string>();
    } catch (const std::exception&) {
        return "application";
    }
}


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

/// Whether these bytes are something a host would execute.
///
/// Used to derive the executable bit at extraction instead of trusting the ZIP
/// external attributes, which no hash and no signature covers. See the call
/// site in extract_payload for why that matters.
///
/// Deliberately a content sniff and nothing more: it decides a permission bit,
/// not what gets run. The manifest names the entrypoint, and the payload-role
/// stage has already checked that the entrypoint really is the kind of image it
/// claims to be -- so a false positive here grants +x to a file nothing
/// executes, and a false negative costs an unusual helper its exec bit.
bool is_executable_content(const std::vector<std::uint8_t>& data) {
    if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' &&
        data[2] == 'L' && data[3] == 'F') {
        return true; // ELF
    }
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') {
        return true; // PE/COFF, for a Windows payload run through a chain
    }
    if (data.size() >= 2 && data[0] == '#' && data[1] == '!') {
        return true; // a script with an interpreter line
    }
    return false;
}

/// FORMAT-0.1 §2 entry-path rules. Returns the reason a path must be
/// rejected, or nullopt when the path is acceptable. Applied to every entry
/// (including directory entries, whose trailing '/' is stripped first).
std::optional<std::string> entry_path_problem(const std::string& raw) {
    if (raw.empty()) return "empty entry path";
    if (raw.size() > limits::kMaxPathBytes) {
        return "entry path exceeds the " +
               std::to_string(limits::kMaxPathBytes) + "-byte limit";
    }
    if (raw.find('\0') != std::string::npos) return "path contains a NUL byte";
    // §1 states entry paths are UTF-8, but it stated it as a WRITER obligation
    // and no reader checked it -- so a name carrying a lone 0xFF byte passed the
    // structure stage and reached the filesystem, and `utf8_segment_to_path`
    // below builds a std::u8string from these bytes on Windows while its own
    // comment says "validated UTF-8". An assumption documented and not enforced.
    //
    // Checked here, with the rest of the §2 path rules, because an entry name
    // BECOMES a filesystem path: an overlong encoding is a second spelling of a
    // character, which is how a segment that does not compare equal to `..` can
    // still decode to it, and every check above compares bytes.
    if (!util::is_valid_utf8(raw)) return "path is not valid UTF-8";
    if (raw.find('\\') != std::string::npos) return "path contains a backslash";
    if (raw.front() == '/') return "absolute path";

    std::string path = raw;
    const bool is_directory = path.back() == '/';
    if (is_directory) path.pop_back();
    if (path.empty()) return "empty entry path";

    const std::vector<std::string> segments = split_segments(path);
    if (segments.size() > limits::kMaxPathDepth) {
        return "entry path exceeds the maximum directory depth (" +
               std::to_string(limits::kMaxPathDepth) + ")";
    }
    for (const std::string& seg : segments) {
        if (seg.empty()) return "empty path segment";
        if (seg.size() > limits::kMaxPathComponentBytes) {
            return "path component exceeds the " +
                   std::to_string(limits::kMaxPathComponentBytes) +
                   "-byte limit";
        }
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

/// The archive must occupy EXACTLY the whole file (HARDENING.md §B): the
/// End-Of-Central-Directory record must be the final 22 bytes (no archive
/// comment — FORMAT §1), and the central directory must end exactly where the
/// EOCD begins (no prepended data, no gap, no ZIP64 sentinel). This rejects
/// trailing data, prepended data, and archive comments that miniz would
/// otherwise tolerate — none of which is covered by the signatures.
bool archive_spans_whole_file(const std::vector<std::uint8_t>& b) {
    if (b.size() < 22) return false;
    const std::size_t eocd = b.size() - 22;
    if (!(b[eocd] == 0x50 && b[eocd + 1] == 0x4b && b[eocd + 2] == 0x05 &&
          b[eocd + 3] == 0x06)) {
        return false; // EOCD not at the tail → comment or trailing data
    }
    auto rd16 = [&](std::size_t o) -> std::uint32_t {
        return static_cast<std::uint32_t>(b[o]) |
               (static_cast<std::uint32_t>(b[o + 1]) << 8);
    };
    auto rd32 = [&](std::size_t o) -> std::uint32_t {
        return static_cast<std::uint32_t>(b[o]) |
               (static_cast<std::uint32_t>(b[o + 1]) << 8) |
               (static_cast<std::uint32_t>(b[o + 2]) << 16) |
               (static_cast<std::uint32_t>(b[o + 3]) << 24);
    };
    if (rd16(eocd + 20) != 0) return false; // non-empty archive comment
    const std::uint64_t cd_size = rd32(eocd + 12);
    const std::uint64_t cd_offset = rd32(eocd + 16);
    return cd_offset + cd_size == eocd; // CD ends exactly at the EOCD
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

/// Cross-check every local file header against the central directory, and
/// account for every byte before it (HARDENING.md §B.5).
///
/// A ZIP says everything twice: once in a local header beside the data, once in
/// the central directory at the end. Readers pick one. This reader picks the
/// central directory -- but until now it never checked that the other copy
/// agreed, and "the two copies disagree" is the classic ZIP ambiguity: two
/// conforming tools read the same file as two different archives. Only one of
/// them is covered by the signature chain, so the other is free bytes.
///
/// Three things were demonstrated to pass before this existed, on validly
/// signed packages:
///
///   a local header naming `payload/../../ev` while the central directory
///   named `payload/data.txt` -- and the independent validator, which reads
///   local names, disagreed with `lexe verify` about the very same file
///
///   a local header declaring a different uncompressed size
///
///   a complete extra local record spliced into the gap between the last
///   entry's data and the central directory, with the EOCD's offset bumped
///   past it. `archive_spans_whole_file` only checks the TAIL -- that the
///   central directory ends where the EOCD begins -- so a gap in the middle
///   was unaccounted space that anything could occupy
///
/// Returns the reason to reject, or nullopt.
std::optional<std::string>
local_header_problem(mz_zip_archive& zip, const std::vector<std::uint8_t>& b,
                     mz_uint count) {
    auto rd16 = [&](std::size_t o) -> std::uint32_t {
        return static_cast<std::uint32_t>(b[o]) |
               (static_cast<std::uint32_t>(b[o + 1]) << 8);
    };
    auto rd32 = [&](std::size_t o) -> std::uint64_t {
        return static_cast<std::uint64_t>(b[o]) |
               (static_cast<std::uint64_t>(b[o + 1]) << 8) |
               (static_cast<std::uint64_t>(b[o + 2]) << 16) |
               (static_cast<std::uint64_t>(b[o + 3]) << 24);
    };

    // Where the central directory begins, from the EOCD that
    // archive_spans_whole_file has already validated.
    const std::size_t eocd = b.size() - 22;
    const std::uint64_t cd_offset = rd32(eocd + 16);

    // Every byte from 0 to cd_offset must be accounted for by exactly the
    // local records the central directory names, laid end to end.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans; // [begin, end)

    for (mz_uint i = 0; i < count; ++i) {
        mz_zip_archive_file_stat st;
        std::memset(&st, 0, sizeof(st));
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            return "cannot read entry record #" + std::to_string(i);
        }
        const std::uint64_t lho = st.m_local_header_ofs;
        if (lho + 30 > b.size()) {
            return "local header for '" + std::string(st.m_filename) +
                   "' lies outside the file";
        }
        if (!(b[lho] == 0x50 && b[lho + 1] == 0x4b && b[lho + 2] == 0x03 &&
              b[lho + 3] == 0x04)) {
            return "local header for '" + std::string(st.m_filename) +
                   "' has a bad signature";
        }

        const std::uint32_t flags = rd16(lho + 6);
        const std::uint32_t method = rd16(lho + 8);
        const std::uint64_t lh_comp = rd32(lho + 18);
        const std::uint64_t lh_uncomp = rd32(lho + 22);
        const std::uint32_t name_len = rd16(lho + 26);
        const std::uint32_t extra_len = rd16(lho + 28);

        if (lho + 30 + name_len + extra_len > b.size()) {
            return "local header for '" + std::string(st.m_filename) +
                   "' is truncated";
        }

        // The NAME. This is the one that matters most: a disagreement here is
        // two readers extracting to two different paths.
        const std::string local_name(
            reinterpret_cast<const char*>(b.data() + lho + 30), name_len);
        const std::string central_name = raw_entry_name(zip, i);
        if (local_name != central_name) {
            return "local header and central directory disagree on an entry "
                   "name ('" +
                   printable(local_name) + "' vs '" + printable(central_name) +
                   "')";
        }
        if (method != st.m_method) {
            return "local header and central directory disagree on the "
                   "compression method for '" +
                   central_name + "'";
        }

        // Sizes. A data descriptor (flag bit 3) legitimately leaves the local
        // sizes zero, with the real values following the data; the reference
        // writer never emits one, but tolerating the zeros costs nothing and
        // rejecting a legal construct for no security gain would be gratuitous.
        const bool has_descriptor = (flags & 0x8u) != 0;
        if (!has_descriptor) {
            if (lh_comp != st.m_comp_size || lh_uncomp != st.m_uncomp_size) {
                return "local header and central directory disagree on the "
                       "size of '" +
                       central_name + "'";
            }
        }

        const std::uint64_t data_begin = lho + 30 + name_len + extra_len;
        std::uint64_t data_end = data_begin + st.m_comp_size;
        if (has_descriptor) {
            // A data descriptor is 12 or 16 bytes: APPNOTE 4.3.9.3 makes its
            // leading `PK\x07\x08` signature word OPTIONAL. Assuming 16
            // unconditionally computed the record's end four bytes too far and
            // rejected a conformant archive as overlapping -- fail-closed, so
            // not a security defect, but a refusal of something legal.
            //
            // The length is derived rather than guessed: look for the signature
            // word exactly where it would be. The compressed size comes from the
            // central directory, which §2.2 has already made authoritative, so
            // this is reading a known location and not scanning.
            const std::uint64_t at = data_begin + st.m_comp_size;
            const bool has_sig_word =
                at + 4 <= b.size() && b[at] == 0x50 && b[at + 1] == 0x4b &&
                b[at + 2] == 0x07 && b[at + 3] == 0x08;
            data_end += has_sig_word ? 16 : 12;
        }
        if (data_end > cd_offset) {
            return "entry '" + central_name +
                   "' extends past the start of the central directory";
        }
        spans.emplace_back(lho, data_end);
    }

    // No gaps, no overlaps, nothing before the first record, and nothing
    // between the last record and the central directory. This is what closes
    // the "ghost local record" case: unaccounted space is space an attacker
    // can use, and no signature covers it.
    std::sort(spans.begin(), spans.end());
    std::uint64_t cursor = 0;
    for (const auto& [begin, end] : spans) {
        if (begin != cursor) {
            return begin < cursor
                       ? std::string("entry data overlaps another entry")
                       : std::string("unaccounted bytes between entries (a "
                                     "record no central-directory entry names)");
        }
        cursor = end;
    }
    if (cursor != cd_offset) {
        return "unaccounted bytes between the last entry and the central "
               "directory";
    }
    return std::nullopt;
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
    // Bound the package size BEFORE loading it into memory (HARDENING.md §F):
    // check the on-disk size so a hostile multi-gigabyte file is never slurped.
    // The bound is FAIL-CLOSED: a path whose size cannot be established is not
    // a package, so it is refused here rather than slipping past the limit.
    {
        std::error_code ec;
        // A missing path keeps its own NotFoundError from slurp() below, so the
        // "file not found" message a mistyped path deserves is not replaced by
        // the kind check.
        if (!fs::exists(lexe_file, ec)) {
            throw NotFoundError(
                "file not found: " + lexe_file.string(),
                "Check the path to the .lexe file.");
        }
        if (!fs::is_regular_file(lexe_file, ec)) {
            // A directory is the common form of this mistake — a developer
            // pointing a package command at the project folder — so say so.
            std::error_code dir_ec;
            if (fs::is_directory(lexe_file, dir_ec)) {
                // Both halves matter: `lexe verify` shows only the message,
                // while the top-level CLI shows the hint. Without a hint here
                // the generic "re-download the package" advice for a failed
                // verification would appear, which is wrong for a folder.
                throw VerificationError(
                    "package: " + lexe_file.string() +
                    " is a directory, not a .lexe package file",
                    "Build a project folder into a package first: `lexe build " +
                        lexe_file.string() + "`.");
            }
            throw VerificationError(
                "package: not a regular file: " + lexe_file.string(),
                "A .lexe package is a single file. Check the path.");
        }
        const auto on_disk = fs::file_size(lexe_file, ec);
        if (ec) {
            throw VerificationError("package: cannot determine the size of " +
                                    lexe_file.string() + ": " + ec.message());
        }
        if (on_disk > limits::kMaxPackageBytes) {
            throw ResourceLimitError(
                "package: file is " + std::to_string(on_disk) +
                " bytes, exceeds the " +
                std::to_string(limits::kMaxPackageBytes) + "-byte limit");
        }
    }
    impl_->bytes = util::slurp(lexe_file); // NotFoundError when missing
    if (!mz_zip_reader_init_mem(&impl_->zip, impl_->bytes.data(),
                                impl_->bytes.size(), 0)) {
        throw VerificationError("package: not a valid ZIP archive: " +
                                lexe_file.string());
    }
    impl_->open = true;

    // Reject trailing/prepended data and archive comments (HARDENING.md §B): a
    // deterministic .lexe is exactly its ZIP archive, so no unsigned bytes can
    // ride along before or after the signed content.
    if (!archive_spans_whole_file(impl_->bytes)) {
        throw VerificationError(
            "package: archive does not span the whole file (trailing/prepended "
            "data or an archive comment)");
    }

    // Bound the entry count before walking the central directory (§F).
    if (mz_zip_reader_get_num_files(&impl_->zip) > limits::kMaxEntryCount) {
        throw ResourceLimitError(
            "package: archive has more than " +
            std::to_string(limits::kMaxEntryCount) + " entries");
    }

    // Every local header must agree with the central directory, and every byte
    // before the central directory must belong to a record it names
    // (HARDENING.md §B.5). Run BEFORE the per-entry rules, because those rules
    // read the central directory and this is what establishes that the central
    // directory is the only view of the archive there is.
    if (const std::optional<std::string> problem = local_header_problem(
            impl_->zip, impl_->bytes, mz_zip_reader_get_num_files(&impl_->zip))) {
        throw VerificationError(
            "package: " + *problem,
            "A ZIP records each entry twice, and these two records disagree. "
            "Two conforming readers would see two different archives, and only "
            "one of them is covered by the package's signatures.");
    }

    // FORMAT-0.1 §2 — validate every entry before anything is trusted.
    std::set<std::string> seen;
    std::set<std::string> seen_casefold; // case-insensitive collision guard
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
        // Case-insensitive collision (HARDENING.md §B): two entries differing
        // only by case (e.g. payload/App and payload/app) would alias on a
        // case-insensitive filesystem, so one could overwrite the other after
        // extraction. Reject them regardless of the host filesystem.
        std::string casefold = name;
        std::transform(casefold.begin(), casefold.end(), casefold.begin(),
                       [](unsigned char c) {
                           return static_cast<char>(
                               (c >= 'A' && c <= 'Z') ? c + 32 : c);
                       });
        if (!seen_casefold.insert(casefold).second) {
            throw VerificationError(
                "package: entry path collides case-insensitively with another: " +
                name);
        }
        // Directory entries are REJECTED, not skipped.
        //
        // They used to be skipped, on the reasoning that a directory record
        // carries no content and so has nothing to smuggle. That reasoning is
        // false, and was demonstrated to be: a ZIP directory record can carry
        // data bytes perfectly well. Worse, because `impl_->files` excludes
        // them, every later rule that walks that vector could not see them --
        // including the `signatures/` exact allowlist, so `signatures/evil/`
        // with a payload attached slipped straight past the check written
        // specifically to stop content appearing there.
        //
        // A skipped entry is an entry no rule applies to, which is the shape of
        // the original smuggling hole. Rejecting is also what HARDENING.md
        // §B.11 already required; the reader simply never did it.
        //
        // The interoperability cost is small and bounded: a `.lexe` is produced
        // by a `.lexe` writer, which never emits these, not by `zip -r`.
        if (mz_zip_reader_is_file_a_directory(&impl_->zip, i)) {
            throw VerificationError(
                "package: rejected entry '" + name + "': directory entry",
                "A .lexe archive stores files only. Directory records carry no "
                "information this format uses, and an entry that no rule "
                "applies to is how content gets in unchecked.");
        }

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

    // The decompression-bomb policy, applied at OPEN rather than at extraction.
    //
    // It used to live only in extract_payload(), which meant `lexe install`
    // refused a bomb and `lexe verify` reported it OK -- and `verify` is the
    // command a CI job, a repository gate or a cautious user runs to decide
    // whether a package is acceptable. A gate that passes what the installer
    // will refuse is worse than no gate: it hands out an assurance the runtime
    // does not honour. (Found by the independent conformance validator in
    // tools/lexe-conformance, which flagged a 411 KB package expanding 1019x
    // that every one of verify's seven stages passed.)
    //
    // Enforced here, in the reader's constructor, so it applies to every
    // consumer at once -- verify, install, info, inspect and anything added
    // later -- instead of being a rule each caller has to remember.
    //
    // Read from the central directory's DECLARED sizes, which costs no
    // decompression: a bomb is refused before a single byte of it is expanded,
    // which is the whole point of the guard. A lying central directory cannot
    // buy anything by understating, because extract_payload() still counts the
    // bytes it actually emits and enforces the same two limits against the
    // real total. Cheap and early here; authoritative there.
    {
        std::uint64_t declared_total = 0;
        for (const Impl::File& f : impl_->files) {
            // Overflow-safe: each entry is <= 1 GiB (read_entry's cap) and
            // entries are <= 65535, so the sum cannot approach UINT64_MAX.
            declared_total += f.entry.uncompressed_size;
        }
        if (declared_total > limits::kMaxTotalUncompressedBytes) {
            throw ResourceLimitError(
                "package: entries declare " + std::to_string(declared_total) +
                    " uncompressed bytes in total, exceeding the " +
                    std::to_string(limits::kMaxTotalUncompressedBytes) +
                    "-byte limit",
                "This package would expand to more than the runtime will "
                "accept. It is either corrupt or deliberately oversized.");
        }
        const std::uint64_t package_size = impl_->bytes.size();
        if (declared_total > limits::kRatioGraceBytes && package_size != 0 &&
            declared_total > package_size * limits::kMaxExpansionRatio) {
            throw ResourceLimitError(
                "package: expands more than " +
                    std::to_string(limits::kMaxExpansionRatio) +
                    "x its packaged size (decompression-bomb guard)",
                "A package this compressible is not a normal application "
                "payload. The runtime refuses it rather than expanding it.");
        }
    }

    // `signatures/` holds EXACTLY the two signature files and nothing else.
    //
    // This closes a hole, and the hole was the signature covering everything in
    // the package except one directory an attacker could write into.
    //
    // §3 excludes the whole `signatures/` PREFIX from hash coverage -- correctly,
    // since a hash document cannot cover a signature over itself -- while §2's
    // top-level allowlist permits the prefix in general. Those two rules met in
    // the middle: any additional entry under `signatures/` was covered by no
    // hash, covered by no signature, and rejected by nothing. Demonstrated
    // against a real package: `signatures/smuggled.bin` (3328 bytes) and
    // `signatures/deep/nested/evil.so` added to a validly signed package, and
    // `lexe verify` reported "verification: OK (signature valid, Ed25519)" with
    // all seven stages green.
    //
    // Nothing in the format needs anything else there, and the reference writer
    // emits only these two, so the rule is an exact allowlist rather than a
    // pattern: a closed set cannot be widened by a filename that happens to look
    // plausible. An extra signature scheme in a later format version gets its own
    // specified name and its own coverage rule; it does not get to arrive
    // unannounced in a directory nothing checks.
    for (const Impl::File& f : impl_->files) {
        if (f.entry.path.rfind("signatures/", 0) != 0) continue;
        if (f.entry.path == "signatures/manifest.sig" ||
            f.entry.path == "signatures/payload.sig") {
            continue;
        }
        throw VerificationError(
            "package: unexpected entry under signatures/: " + f.entry.path,
            "Only signatures/manifest.sig and signatures/payload.sig may appear "
            "there. Nothing else under that prefix is covered by the package's "
            "hashes or its signatures, so a package carrying one is carrying "
            "content nobody signed.");
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
    // Definitive Architecture §15.1 — the ROLE decides whether payload/ is
    // required. An installable application in bundled mode must carry payload
    // bytes; a launch reference names an installed application and carries
    // none. The role is read here as a bare structural hint; the manifest
    // module still performs full §5 validation (and the payload-role stage of
    // the §6 pipeline still checks that the bytes match the declared role), so
    // a lying `role` cannot buy anything — it only moves which rule rejects it.
    if (declared_role(read_entry("lexe.json")) != "launch") {
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
    // Bound the allocation by the DECLARED size before extracting (§F). A ZIP
    // bomb that declares a huge uncompressed size is rejected here, before
    // miniz tries to allocate it; a declaration that lies small is caught by
    // miniz (the decompressed stream cannot exceed the allocated buffer).
    if (f.entry.uncompressed_size > limits::kMaxEntryUncompressedBytes) {
        throw VerificationError(
            "package: entry \"" + entry_path + "\" declares " +
            std::to_string(f.entry.uncompressed_size) +
            " uncompressed bytes, exceeds the per-entry limit of " +
            std::to_string(limits::kMaxEntryUncompressedBytes));
    }
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

    // Track ACTUAL emitted bytes across the whole extraction (§F): a per-entry
    // cap alone cannot stop many-entry bombs, and the declared sizes are never
    // trusted for the aggregate — read_entry returns the real bytes.
    std::uint64_t total_emitted = 0;
    const std::uint64_t package_size = impl_->bytes.size();

    // The publisher's signed list of executable members (§3.1.1), read once.
    //
    // Absent for a package written before the declaration existed, and that is
    // not an error: nullopt means "fall back to the content sniff" rather than
    // "nothing is executable", because the latter would silently break every
    // existing package's helper binaries.
    //
    // Parsed leniently on purpose. This runs AFTER verification, so the bytes
    // are authentic; the only question is whether this reader understands them.
    // A malformed or unexpected shape falls back rather than failing an
    // extraction that has already been authorised.
    std::optional<std::set<std::string>> declared_executable;
    try {
        const nlohmann::json doc = nlohmann::json::parse(
            read_entry("metadata/hashes.json"), nullptr, false);
        if (doc.is_object() && doc.contains("executable") &&
            doc["executable"].is_array()) {
            std::set<std::string> names;
            for (const nlohmann::json& item : doc["executable"]) {
                if (item.is_string()) names.insert(item.get<std::string>());
            }
            declared_executable = std::move(names);
        }
    } catch (const std::exception&) {
        // Fall back to the sniff.
    }

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

        // read_entry enforces the per-entry cap and returns the real bytes.
        const std::vector<std::uint8_t> data = read_entry(path);
        // Overflow-safe: each entry <= 1 GiB and entries <= 65535, so the sum
        // cannot approach UINT64_MAX.
        total_emitted += data.size();
        if (total_emitted > limits::kMaxTotalUncompressedBytes) {
            throw ResourceLimitError(
                "package: total uncompressed size exceeds the " +
                std::to_string(limits::kMaxTotalUncompressedBytes) +
                "-byte limit");
        }
        // Expansion-ratio guard: once past the grace size, a package that
        // expands more than kMaxExpansionRatio× its own size is a bomb.
        // package_size * ratio cannot overflow (package_size <= 2 GiB).
        if (total_emitted > limits::kRatioGraceBytes && package_size != 0 &&
            total_emitted > package_size * limits::kMaxExpansionRatio) {
            throw ResourceLimitError(
                "package: expands more than " +
                std::to_string(limits::kMaxExpansionRatio) +
                "× its packaged size (decompression-bomb guard)");
        }

        fs::create_directories(resolved.parent_path());
        util::spit(resolved, data);

#ifndef _WIN32
        // The executable bit is derived from the CONTENT, never from the
        // recorded mode. This is a security fix, not a simplification.
        //
        // A ZIP entry's Unix mode lives in the central directory's external
        // attributes. Nothing covers it: hashes.json digests file CONTENT, and
        // the two signatures cover lexe.json and hashes.json. So the mode was
        // the one class of byte in a package that could be altered after
        // signing and still verify. Demonstrated: flipping a data file's
        // recorded mode to 04755 on a validly signed package left
        // `lexe verify` reporting OK with every stage green, and `lexe install`
        // then wrote that file to disk executable.
        //
        // Permissions are named explicitly in the integrity invariant
        // (FORMAT-0.1 §3), so "it verified" has to mean the permissions are
        // intact too. There were three ways to get there:
        //
        //   cover the mode in hashes.json   a format change, and hashes.json
        //                                   values would stop being digests
        //   reject any non-canonical mode   does not help: 0644 -> 0755 is a
        //                                   flip WITHIN the allowed pair
        //   derive it from covered bytes    no format change, and the answer
        //                                   comes from data that IS signed
        //
        // The third is taken. Content is hash-covered, so a mode derived from
        // content inherits that coverage, and the unsigned attribute stops
        // being able to influence anything at all -- which is what puts it
        // legitimately outside the envelope rather than sitting in a gap.
        //
        // The publisher's signed DECLARATION decides, when there is one.
        //
        // An earlier draft derived executability from content alone (ELF, PE,
        // `#!`). That closed the hole but replaced a declaration with a
        // heuristic at a security boundary, and the heuristic is lossy in both
        // directions: a `.jar`, a .NET assembly, a WASM module and a
        // shebang-less helper script are all legitimately executable and match
        // none of the three magics, while a data file that happens to begin
        // `MZ` or `#!` would gain +x it was never given.
        //
        // So `metadata/hashes.json` carries an `executable` list, inside the
        // document payload.sig already covers. Publisher intent is preserved
        // AND signed. The content sniff remains only as the fallback for a
        // package that carries no declaration, where guessing beats refusing to
        // run a helper the publisher marked executable.
        const bool exec = declared_executable.has_value()
                              ? declared_executable->count(path) != 0
                              : is_executable_content(data);
        if (exec) {
            std::error_code ec;
            fs::permissions(resolved,
                            fs::perms::owner_exec | fs::perms::group_exec |
                                fs::perms::others_exec,
                            fs::perm_options::add, ec);
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

/// Owns the heap buffer `mz_zip_writer_finalize_heap_archive` hands back.
///
/// That call TRANSFERS ownership — it clears the archive's `m_pMem`, so the
/// writer's own `mz_zip_writer_end` no longer has anything to free and the
/// buffer is the caller's to release. Missing that leaked one whole archive
/// per `pack`: invisible in a CLI that exits immediately afterwards, and a
/// steady leak the size of every package built in `lexe-builder`, which does
/// not. Found by AddressSanitizer, not by reading the code.
struct ZipHeapBufferGuard {
    void* buf = nullptr;
    ~ZipHeapBufferGuard() {
        if (buf != nullptr) MZ_FREE(buf);
    }
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
    // here we require well-formed, duplicate-key-free JSON (HARDENING.md §E) so
    // a manifest the reader would later reject cannot be shipped and signed.
    std::vector<std::uint8_t> manifest_bytes =
        util::slurp(inputs.manifest_file);
    {
        const nlohmann::json parsed = json_strict::parse(
            std::string_view(reinterpret_cast<const char*>(manifest_bytes.data()),
                             manifest_bytes.size()),
            "manifest", limits::kMaxManifestBytes);
        if (!parsed.is_object()) {
            throw Error("pack: manifest is not a valid JSON object: " +
                        inputs.manifest_file.string());
        }
    }
    entries.push_back({"lexe.json", manifest_bytes});

    const std::size_t before_payload = entries.size();
    collect_tree(inputs.payload_dir, "payload/", entries);
    if (entries.size() == before_payload && !inputs.allow_empty_payload) {
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
    // The publisher's DECLARATION of which members are executable (§3.1.1).
    //
    // It lives here, inside the document payload.sig covers, because the ZIP
    // external-attribute mode is covered by nothing and so cannot be trusted.
    // A declaration that is signed keeps the publisher's intent authoritative
    // -- `nlohmann::json`'s object keeps insertion order for `ordered_json`
    // only, so this is sorted explicitly to stay deterministic (§1).
    std::vector<std::string> executable;
    for (const WriteEntry& e : entries) {
        if (e.path == "lexe.json") continue;
        files[e.path] = sha256_hex_of(e.bytes);
        // Only PAYLOAD entries can be declared executable, and the filter is
        // load-bearing rather than tidiness.
        //
        // The declaration governs extraction, and only `payload/` is ever
        // extracted -- so declaring `icons/128.png` executable states something
        // that can never be honoured, and §3.6 rejects it. That is not
        // hypothetical: on a filesystem without Unix permission bits (a
        // Windows drive mounted under WSL reports every file as 0755) every
        // icon came back executable, and the first package built on one was
        // refused by its own verifier.
        if (e.mode == kModeExec && e.path.rfind("payload/", 0) == 0) {
            executable.push_back(e.path);
        }
    }
    std::sort(executable.begin(), executable.end());
    nlohmann::json hashes = {{"algorithm", "sha256"}, {"files", files}};
    // ALWAYS emitted, including as an empty array.
    //
    // An earlier version omitted it when nothing was executable, to keep output
    // byte-identical to a package written before the member existed. That made
    // "nothing here is executable" inexpressible: absent means "fall back to the
    // content sniff", so a package whose only oddity was a data file beginning
    // `#!` or `MZ` got an executable bit its publisher never granted -- the
    // false positive the declaration was introduced to remove, reintroduced for
    // exactly the packages that needed it least.
    //
    // Determinism is unaffected: the same input tree still produces the same
    // bytes. Only the comparison against older output changes, and a writer is
    // allowed to improve.
    hashes["executable"] = executable;
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
    // central directory (FORMAT-0.1 §1/§D) before writing to disk. The buffer
    // belongs to us from here (see ZipHeapBufferGuard).
    const ZipHeapBufferGuard heap_buffer{buf};
    std::vector<std::uint8_t> archive(
        static_cast<const std::uint8_t*>(buf),
        static_cast<const std::uint8_t*>(buf) + buf_size);
    patch_central_directory_modes(archive, entries);
    util::spit(out_lexe, archive);
}

} // namespace lexe

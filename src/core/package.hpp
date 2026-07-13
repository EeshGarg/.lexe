#pragma once
// package — reading and writing `.lexe` ZIP containers. PackageReader
// enforces the entry rules of FORMAT-0.1 §2 and extracts zip-slip-safely
// (security invariant #1). PackageWriter produces the deterministic archives
// of FORMAT-0.1 §1 and generates hashes.json (§3) + signatures (§4).

#include "core/crypto.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace lexe {

/// One archive entry as listed by PackageReader.
struct PackageEntry {
    std::string path;                 // full entry path, forward slashes
    std::uint64_t uncompressed_size = 0;
};

/// Read-only view of a `.lexe` file (FORMAT-0.1 §2).
///
/// The constructor opens the archive and rejects it (VerificationError) when
/// any §2 rule is violated: absolute paths, `..` segments, backslashes, NUL,
/// drive designators, first segment not in the allowed set, duplicate paths,
/// symlink entries, or a missing required entry.
class PackageReader {
public:
    explicit PackageReader(const std::filesystem::path& lexe_file);
    ~PackageReader();
    PackageReader(PackageReader&&) noexcept;
    PackageReader& operator=(PackageReader&&) noexcept;
    PackageReader(const PackageReader&) = delete;
    PackageReader& operator=(const PackageReader&) = delete;

    /// The archive path this reader was opened on.
    const std::filesystem::path& file() const;

    /// All entries, sorted by path (directories excluded).
    std::vector<PackageEntry> entries() const;

    /// Whether an entry with this exact path exists.
    bool has_entry(const std::string& entry_path) const;

    /// Decompressed bytes of one entry. Throws NotFoundError when absent.
    std::vector<std::uint8_t> read_entry(const std::string& entry_path) const;

    /// Extract every `payload/` entry into dest_dir (stripping the `payload/`
    /// prefix). Zip-slip safe: every resolved destination must remain under
    /// dest_dir (checked with weakly_canonical — security invariant #1).
    void extract_payload(const std::filesystem::path& dest_dir) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Deterministic `.lexe` writer (`lexe pack`, FORMAT-0.1 §1): entries in
/// lexicographic byte order, zeroed timestamps (MINIZ_NO_TIME), forward-slash
/// UTF-8 paths, DEFLATE level 9 (STORE below 64 bytes), no ZIP64/encryption/
/// comments. Packing the same input twice yields byte-identical output.
class PackageWriter {
public:
    /// Input tree for one package (CLI `lexe pack` conventions).
    struct Inputs {
        /// Directory whose contents become `payload/…` (required).
        std::filesystem::path payload_dir;
        /// File stored verbatim as `lexe.json` (required; must be a valid
        /// JSON object — full §5 validation is the manifest module's job).
        std::filesystem::path manifest_file;
        /// Optional directory stored as `icons/…`.
        std::optional<std::filesystem::path> icons_dir;
        /// Optional directory stored as `metadata/…` (hashes.json is always
        /// generated and must not exist here).
        std::optional<std::filesystem::path> metadata_dir;
    };

    /// Build `out_lexe`: collect entries, compute `metadata/hashes.json`
    /// (FORMAT-0.1 §3), sign `lexe.json` and `hashes.json` bytes with `key`
    /// into `signatures/*.sig` (FORMAT-0.1 §4), write deterministically.
    /// Throws Error/VerificationError on invalid inputs.
    static void write(const Inputs& inputs, const crypto::KeyPair& key,
                      const std::filesystem::path& out_lexe);
};

} // namespace lexe

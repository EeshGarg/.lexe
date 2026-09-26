// limits — the ONE place every resource bound for untrusted package input is
// defined (HARDENING.md §F: "Avoid arbitrary limits scattered throughout the
// codebase. Put them in one reviewed policy definition.").
//
// Every value is treated as hostile: sizes and counts declared by a package are
// never trusted, are checked before allocation where possible, and decompression
// tracks ACTUAL emitted bytes rather than the archive's declared sizes. All
// arithmetic against these limits must be overflow-safe (the values are chosen
// to leave head-room below SIZE_MAX so `a + b > limit` comparisons cannot wrap
// on any supported platform).
//
// Changing a limit is a policy change: adjust it here, update the boundary tests
// in tests/test_limits.cpp, and note it in docs/HARDENING.md.

#pragma once

#include <cstddef>
#include <cstdint>

namespace lexe::limits {

// ----------------------------------------------------------------- container
/// Maximum size of a whole .lexe file the reader will load (mem-backed reader).
inline constexpr std::uint64_t kMaxPackageBytes = 2ull * 1024 * 1024 * 1024; // 2 GiB
/// Maximum number of archive entries (ZIP central-directory records).
inline constexpr std::size_t kMaxEntryCount = 65535;

// ----------------------------------------------------------- decompression
/// Maximum uncompressed size of a single archive entry.
inline constexpr std::uint64_t kMaxEntryUncompressedBytes =
    1ull * 1024 * 1024 * 1024; // 1 GiB
/// Maximum total uncompressed bytes emitted across a whole extraction.
inline constexpr std::uint64_t kMaxTotalUncompressedBytes =
    2ull * 1024 * 1024 * 1024; // 2 GiB
/// Maximum overall expansion ratio (total uncompressed / package size). A ZIP
/// bomb has an enormous ratio; legitimate packages are well under this. Only
/// enforced once the emitted total is large enough that the ratio is meaningful
/// (see kRatioGraceBytes) so small highly-compressible files are not rejected.
inline constexpr std::uint64_t kMaxExpansionRatio = 200;
/// Below this many emitted bytes the expansion-ratio guard does not apply.
inline constexpr std::uint64_t kRatioGraceBytes = 16ull * 1024 * 1024; // 16 MiB

// ------------------------------------------------------------------- paths
/// Maximum bytes in a whole entry path.
inline constexpr std::size_t kMaxPathBytes = 1024;
/// Maximum bytes in a single '/'-separated path component.
inline constexpr std::size_t kMaxPathComponentBytes = 255;
/// Maximum directory depth (number of '/'-separated components).
inline constexpr std::size_t kMaxPathDepth = 64;

// -------------------------------------------------- JSON document budgets
// Checked against the raw text BEFORE the DOM is built (json_strict).
inline constexpr std::size_t kMaxManifestBytes = 1024 * 1024;      // 1 MiB
inline constexpr std::size_t kMaxHashesBytes = 16 * 1024 * 1024;   // 16 MiB
inline constexpr std::size_t kMaxRecordBytes = 1024 * 1024;        // 1 MiB
inline constexpr std::size_t kMaxJournalBytes = 1024 * 1024;       // 1 MiB
inline constexpr std::size_t kMaxUpdateJsonBytes = 1024 * 1024;    // 1 MiB
inline constexpr std::size_t kMaxKeyfileBytes = 64 * 1024;         // 64 KiB

// ------------------------------------------------- manifest field budgets
inline constexpr std::size_t kMaxIdBytes = 255;
inline constexpr std::size_t kMaxNameBytes = 1024;
inline constexpr std::size_t kMaxVersionBytes = 256;
/// Encoded publisher key string ("ed25519:" + base64(32) = 52 chars); allow a
/// little slack but reject anything absurd before base64-decoding.
inline constexpr std::size_t kMaxKeyFieldBytes = 128;

// ----------------------------------------------------------- signatures
/// Ed25519 raw signature and public-key lengths are EXACT, not maxima.
inline constexpr std::size_t kEd25519SignatureBytes = 64;
inline constexpr std::size_t kEd25519PublicKeyBytes = 32;
inline constexpr std::size_t kEd25519SeedBytes = 32;

} // namespace lexe::limits

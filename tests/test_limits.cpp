// limits / bounded-extraction tests (HARDENING.md §F). The multi-gigabyte caps
// (package size, per-entry, total uncompressed, 65535 entries) are not
// practical to exercise with real files; those are proven against crafted raw
// archives in the malformed-package corpus (test_hostile_packages.cpp). Here we
// prove the guards that CAN be driven with a real package end-to-end: the
// decompression-bomb expansion-ratio guard, and the path length / component /
// depth caps (enforced by the shared entry_path_problem, reachable through
// PackageWriter).

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/limits.hpp"
#include "core/package.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace {

/// Pack a project whose payload also contains the extra files in `extra`
/// (relative path under payload/ -> bytes). Returns the .lexe path.
fs::path pack_with_payload(
    const fs::path& work, const lexe::crypto::KeyPair& key,
    const std::vector<std::pair<std::string, std::string>>& extra) {
    lexe::test::TestAppSpec spec;
    spec.public_key = lexe::test::encode_public_key_str(key.public_key);
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(work / "tree", spec);
    for (const auto& [rel, bytes] : extra) {
        lexe::util::spit(tree.payload_dir / fs::path(rel),
                         std::string_view(bytes));
    }
    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path out = work / "app.lexe";
    lexe::PackageWriter::write(inputs, key, out);
    return out;
}

} // namespace

TEST_SUITE("limits") {

TEST_CASE("the resource policy is internally consistent") {
    // Sanity: the grace size is below the total cap, and the caps leave head-
    // room below SIZE_MAX so `a + b > limit` cannot wrap (see limits.hpp).
    CHECK(lexe::limits::kRatioGraceBytes < lexe::limits::kMaxTotalUncompressedBytes);
    CHECK(lexe::limits::kMaxEntryUncompressedBytes <=
          lexe::limits::kMaxTotalUncompressedBytes);
    CHECK(lexe::limits::kMaxPathComponentBytes <= lexe::limits::kMaxPathBytes);
}

TEST_CASE("a highly-compressible payload trips the expansion-ratio guard") {
    lexe::test::TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();

    // A payload that decompresses to more than the grace size but packs tiny
    // (zeros deflate to almost nothing) — a classic decompression bomb shape.
    const std::size_t big = lexe::limits::kRatioGraceBytes + 2 * 1024 * 1024;
    const fs::path pkg =
        pack_with_payload(home.path(), key,
                          {{"big.bin", std::string(big, '\0')}});

    // The package on disk is far smaller than what it expands to.
    CHECK(fs::file_size(pkg) * lexe::limits::kMaxExpansionRatio < big);

    const lexe::PackageReader reader(pkg);
    const fs::path dest = home.path() / "out";
    CHECK_THROWS_WITH_AS(reader.extract_payload(dest),
                         doctest::Contains("decompression-bomb"),
                         lexe::VerificationError);
}

TEST_CASE("a normal package extracts without tripping the ratio guard") {
    lexe::test::TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    // Incompressible-ish small content stays well under the grace size.
    const fs::path pkg = pack_with_payload(
        home.path(), key, {{"data.txt", std::string("hello world\n")}});
    const lexe::PackageReader reader(pkg);
    CHECK_NOTHROW(reader.extract_payload(home.path() / "out"));
}

// NB: the over-long path-COMPONENT cap (255 bytes) cannot be driven through a
// real file — the OS itself refuses a 256-byte filename — so it is proven
// against a crafted archive in test_hostile_packages.cpp, together with the
// whole-path-length, package-size, entry-count and per-entry/total caps.

TEST_CASE("PackageWriter rejects an over-deep path (§F depth cap)") {
    lexe::test::TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    std::string deep;
    for (std::size_t i = 0; i < lexe::limits::kMaxPathDepth + 1; ++i) {
        deep += "d/";
    }
    deep += "f";
    CHECK_THROWS_WITH_AS(pack_with_payload(home.path(), key, {{deep, "x"}}),
                         doctest::Contains("depth"), lexe::Error);
}

} // TEST_SUITE("limits")

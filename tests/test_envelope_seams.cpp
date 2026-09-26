// Integrity-envelope seams (independent test engineer).
//
// The standing invariant under test (FORMAT-0.1 §3): "Every byte of a package
// that can influence installation, execution, identity, permissions,
// compatibility, or user-visible package behaviour MUST lie inside the
// integrity envelope, except the cryptographic signature material whose
// relationship to the signed material is defined."
//
// Each case is a validly-SIGNED package mutated at the ZIP-byte level AFTER
// signing, so `lexe.json` and `metadata/hashes.json` — and therefore both
// signatures — are untouched and still verify. The question is whether the
// mutated, unsigned bytes are nevertheless prevented from mattering.
//
// STATUS (Mission 3 re-verification): ALL FOUR PASS.
//   * "recorded mode cannot change what lands on disk"  PASSES (FORMAT §3.1.1)
//   * "directory entries are rejected"                  PASSES (FORMAT §2.2)
//   * "local/central disagreement is rejected"          PASSES (FORMAT §2.2)
//   * "a data descriptor is tolerated in both encodings" PASSES (FORMAT §2.2)
//
// The data-descriptor case was added FAILING in Mission 2 (the contiguity check
// assumed a 16-byte descriptor, so the 12-byte form — APPNOTE 4.3.9.3 makes the
// 0x08074b50 signature word optional — was reported as a bogus overlap). It now
// passes; keep the no-signature-word subcase, since that is the encoding that
// regressed and the one no writer in this tree emits.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/error.hpp"
#include "lexe/base/util.hpp"
#include "lexe/package/package.hpp"
#include "lexe/verify/verify.hpp"

#include <miniz/miniz.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;
using namespace lexe::test;

namespace {

std::uint32_t rd32(const std::vector<std::uint8_t>& b, std::size_t o) {
    return static_cast<std::uint32_t>(b[o]) |
           (static_cast<std::uint32_t>(b[o + 1]) << 8) |
           (static_cast<std::uint32_t>(b[o + 2]) << 16) |
           (static_cast<std::uint32_t>(b[o + 3]) << 24);
}
std::uint16_t rd16(const std::vector<std::uint8_t>& b, std::size_t o) {
    return static_cast<std::uint16_t>(b[o]) |
           (static_cast<std::uint16_t>(b[o + 1]) << 8);
}
void wr32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
    b[o] = v & 0xff;
    b[o + 1] = (v >> 8) & 0xff;
    b[o + 2] = (v >> 16) & 0xff;
    b[o + 3] = (v >> 24) & 0xff;
}
void put32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(v & 0xff);
    b.push_back((v >> 8) & 0xff);
    b.push_back((v >> 16) & 0xff);
    b.push_back((v >> 24) & 0xff);
}
void put16(std::vector<std::uint8_t>& b, std::uint16_t v) {
    b.push_back(v & 0xff);
    b.push_back((v >> 8) & 0xff);
}

/// Visit each central-directory record; `fn(name, record_offset)`.
template <typename F>
void for_each_cd_record(std::vector<std::uint8_t>& b, F fn) {
    REQUIRE(b.size() >= 22);
    const std::size_t eocd = b.size() - 22;
    std::size_t p = rd32(b, eocd + 16);
    const std::uint16_t n = rd16(b, eocd + 10);
    for (std::uint16_t i = 0; i < n; ++i) {
        REQUIRE(rd32(b, p) == 0x02014b50u);
        const std::uint16_t nlen = rd16(b, p + 28);
        const std::uint16_t elen = rd16(b, p + 30);
        const std::uint16_t clen = rd16(b, p + 32);
        fn(std::string(reinterpret_cast<const char*>(&b[p + 46]), nlen), p);
        p += 46 + nlen + elen + clen;
    }
}

/// Set the external-attribute high word (Unix mode) of one entry.
bool patch_central_mode(std::vector<std::uint8_t>& b, const std::string& entry,
                        std::uint32_t unix_mode) {
    bool hit = false;
    for_each_cd_record(b, [&](const std::string& name, std::size_t p) {
        if (name == entry) {
            wr32(b, p + 38, unix_mode << 16);
            hit = true;
        }
    });
    return hit;
}

/// Set the DOS *directory* attribute bit on one entry — the second spelling of
/// "directory entry", and the one with a normal-looking name, which is how a
/// smuggled member originally walked past the §3.2 allowlist.
bool patch_dos_directory_bit(std::vector<std::uint8_t>& b,
                             const std::string& entry) {
    bool hit = false;
    for_each_cd_record(b, [&](const std::string& name, std::size_t p) {
        if (name == entry) {
            wr32(b, p + 38, rd32(b, p + 38) | 0x10u);
            hit = true;
        }
    });
    return hit;
}

/// Rewrite the LOCAL-header copy of a name (same length) leaving the central
/// name intact, so the two views disagree (FORMAT-0.1 §2.2).
bool patch_local_name(std::vector<std::uint8_t>& b, const std::string& central,
                      const std::string& local_same_len) {
    REQUIRE(central.size() == local_same_len.size());
    for (std::size_t p = 0; p + 30 < b.size(); ++p) {
        if (rd32(b, p) != 0x04034b50u) continue;
        if (rd16(b, p + 26) != central.size()) continue;
        if (std::string(reinterpret_cast<const char*>(&b[p + 30]),
                        central.size()) != central) {
            continue;
        }
        std::memcpy(&b[p + 30], local_same_len.data(), local_same_len.size());
        return true;
    }
    return false;
}

/// Decompressed content of every entry of a package, by path.
std::map<std::string, std::vector<std::uint8_t>> read_all(const fs::path& p) {
    std::map<std::string, std::vector<std::uint8_t>> out;
    PackageReader reader(p);
    for (const PackageEntry& e : reader.entries()) {
        out[e.path] = reader.read_entry(e.path);
    }
    return out;
}

/// Rebuild an archive from (path -> bytes), STOREing every entry, and put a
/// data descriptor (general-purpose bit 3) on `dd_entries`. `with_sig_word`
/// selects whether the descriptor carries the optional 0x08074b50 signature —
/// PKWARE APPNOTE 4.3.9.3 makes it optional, and FORMAT-0.1 §2.2 tolerates
/// data descriptors without qualification.
void build_with_data_descriptors(
    const std::map<std::string, std::vector<std::uint8_t>>& blobs,
    const std::vector<std::string>& dd_entries, bool with_sig_word,
    const fs::path& dst) {
    std::vector<std::uint8_t> out;
    std::map<std::string, std::uint32_t> offsets;

    for (const auto& [name, data] : blobs) {
        const bool dd = std::find(dd_entries.begin(), dd_entries.end(), name) !=
                        dd_entries.end();
        const std::uint32_t crc = static_cast<std::uint32_t>(
            mz_crc32(MZ_CRC32_INIT, data.data(), data.size()));
        offsets[name] = static_cast<std::uint32_t>(out.size());
        put32(out, 0x04034b50u);
        put16(out, 20);
        put16(out, dd ? 0x08 : 0x00);
        put16(out, 0); // STORE
        put16(out, 0);
        put16(out, 0);
        put32(out, dd ? 0 : crc);
        put32(out, dd ? 0 : static_cast<std::uint32_t>(data.size()));
        put32(out, dd ? 0 : static_cast<std::uint32_t>(data.size()));
        put16(out, static_cast<std::uint16_t>(name.size()));
        put16(out, 0);
        out.insert(out.end(), name.begin(), name.end());
        out.insert(out.end(), data.begin(), data.end());
        if (dd) {
            if (with_sig_word) put32(out, 0x08074b50u);
            put32(out, crc);
            put32(out, static_cast<std::uint32_t>(data.size()));
            put32(out, static_cast<std::uint32_t>(data.size()));
        }
    }

    const std::uint32_t cd_off = static_cast<std::uint32_t>(out.size());
    for (const auto& [name, data] : blobs) {
        const bool dd = std::find(dd_entries.begin(), dd_entries.end(), name) !=
                        dd_entries.end();
        const std::uint32_t crc = static_cast<std::uint32_t>(
            mz_crc32(MZ_CRC32_INIT, data.data(), data.size()));
        put32(out, 0x02014b50u);
        put16(out, (3 << 8) | 20);
        put16(out, 20);
        put16(out, dd ? 0x08 : 0x00);
        put16(out, 0);
        put16(out, 0);
        put16(out, 0);
        put32(out, crc);
        put32(out, static_cast<std::uint32_t>(data.size()));
        put32(out, static_cast<std::uint32_t>(data.size()));
        put16(out, static_cast<std::uint16_t>(name.size()));
        put16(out, 0);
        put16(out, 0);
        put16(out, 0);
        put16(out, 0);
        put32(out, 0644u << 16);
        put32(out, offsets[name]);
        out.insert(out.end(), name.begin(), name.end());
    }
    const std::uint32_t cd_size = static_cast<std::uint32_t>(out.size()) - cd_off;

    put32(out, 0x06054b50u);
    put16(out, 0);
    put16(out, 0);
    put16(out, static_cast<std::uint16_t>(blobs.size()));
    put16(out, static_cast<std::uint16_t>(blobs.size()));
    put32(out, cd_size);
    put32(out, cd_off);
    put16(out, 0);

    util::spit(dst, out);
}

bool verify_ok(const fs::path& pkg) {
    return verify_package(pkg, /*check_architecture=*/false).ok();
}

fs::path signed_package(const fs::path& work, const crypto::KeyPair& key) {
    TestAppSpec spec;
    spec.architectures = {host_architecture()};
    return make_test_package(work, key, spec);
}

} // namespace

TEST_SUITE("envelope-seams") {

// FORMAT-0.1 §3.1.1 — the recorded mode is outside the envelope and therefore
// MUST be inert. The property that matters is not "verification fails" (it
// deliberately does not; nothing verification checks has changed) but that the
// unsigned byte cannot change what lands on disk. Extract both the original and
// a mode-flipped copy and require identical permissions for every file.
TEST_CASE("the recorded mode cannot change what lands on disk") {
    TempLexeHome home;
    const fs::path work = home.path() / "w";
    fs::create_directories(work);
    const crypto::KeyPair key = make_keypair();
    const fs::path pkg = signed_package(work, key);
    REQUIRE(verify_ok(pkg));

    std::vector<std::uint8_t> bytes = util::slurp(pkg);
    // 04755: setuid + exec, on an ordinary 0644 data file, and a mode the
    // writer can never emit (§1 forbids special bits).
    REQUIRE(patch_central_mode(bytes, "payload/data.txt", 04755));
    const fs::path mutated = work / "mode-flip.lexe";
    util::spit(mutated, bytes);

    // Still verifies — by design (§3.1.1).
    CHECK(verify_ok(mutated));

    const fs::path a = work / "out-original";
    const fs::path b = work / "out-mutated";
    PackageReader(pkg).extract_payload(a);
    PackageReader(mutated).extract_payload(b);

    for (fs::recursive_directory_iterator it(a), end; it != end; ++it) {
        if (!it->is_regular_file()) continue;
        const fs::path rel = fs::relative(it->path(), a);
        const fs::path other = b / rel;
        REQUIRE(fs::exists(other));
        CAPTURE(rel.string());
        CHECK(fs::status(it->path()).permissions() ==
              fs::status(other).permissions());
    }

    // And specifically: no setuid reaches the filesystem, and a data file does
    // not become executable.
    const fs::perms p = fs::status(b / "data.txt").permissions();
    CHECK((p & fs::perms::set_uid) == fs::perms::none);
    CHECK((p & fs::perms::owner_exec) == fs::perms::none);
}

// FORMAT-0.1 §2.2 — a reader MUST reject a ZIP directory entry. Two spellings
// exist; this pins the DOS-attribute-bit spelling, which has an ordinary-looking
// name and is the one that walked past the §3.2 allowlist (that check only ever
// inspected non-directory records). The trailing-slash spelling is covered by
// the python reproducer, since miniz's writer refuses to emit such a name.
TEST_CASE("directory entries are rejected (FORMAT-0.1 §2.2)") {
    TempLexeHome home;
    const fs::path work = home.path() / "w";
    fs::create_directories(work);
    const crypto::KeyPair key = make_keypair();
    const fs::path pkg = signed_package(work, key);
    REQUIRE(verify_ok(pkg));

    std::vector<std::uint8_t> bytes = util::slurp(pkg);
    REQUIRE(patch_dos_directory_bit(bytes, "payload/data.txt"));
    const fs::path mutated = work / "dos-dir-bit.lexe";
    util::spit(mutated, bytes);

    CHECK_FALSE(verify_ok(mutated));
}

// FORMAT-0.1 §2.2 — the central directory is authoritative, and a reader MUST
// reject an archive whose local header disagrees with it. A local header naming
// `payload/../../ev` beside a central directory naming `payload/data.txt` is the
// concrete case the section cites.
TEST_CASE("local/central header disagreement is rejected (FORMAT-0.1 §2.2)") {
    TempLexeHome home;
    const fs::path work = home.path() / "w";
    fs::create_directories(work);
    const crypto::KeyPair key = make_keypair();
    const fs::path pkg = signed_package(work, key);
    REQUIRE(verify_ok(pkg));

    std::vector<std::uint8_t> bytes = util::slurp(pkg);
    REQUIRE(patch_local_name(bytes, "payload/data.txt", "payload/../../ev"));
    const fs::path mutated = work / "name-mismatch.lexe";
    util::spit(mutated, bytes);

    CHECK_FALSE(verify_ok(mutated));
}

// FORMAT-0.1 §2.2: "A data descriptor (general-purpose bit 3) is tolerated."
// Stated without qualification. PKWARE APPNOTE 4.3.9.3 makes the descriptor's
// 0x08074b50 signature word OPTIONAL, and writers exist that omit it.
//
// Both encodings must be accepted. The no-signature-word form regressed once
// (a 16-byte descriptor was assumed, so the 12-byte form computed a record end
// four bytes long and reported a bogus overlap); the descriptor's extent is
// derivable from the central directory's compressed size, which §2.2 has already
// made authoritative, rather than guessable. No writer in this tree emits a data
// descriptor, so this case is the only guard on that path.
TEST_CASE("a data descriptor is tolerated in both encodings (FORMAT-0.1 §2.2)") {
    TempLexeHome home;
    const fs::path work = home.path() / "w";
    fs::create_directories(work);
    const crypto::KeyPair key = make_keypair();
    const fs::path pkg = signed_package(work, key);
    REQUIRE(verify_ok(pkg));

    const std::map<std::string, std::vector<std::uint8_t>> blobs = read_all(pkg);

    SUBCASE("no data descriptors (control)") {
        const fs::path out = work / "dd-none.lexe";
        build_with_data_descriptors(blobs, {}, true, out);
        CHECK(verify_ok(out));
    }
    SUBCASE("descriptor WITH the optional signature word") {
        const fs::path out = work / "dd-sig.lexe";
        build_with_data_descriptors(blobs, {"payload/data.txt"}, true, out);
        CHECK(verify_ok(out));
    }
    SUBCASE("descriptor WITHOUT the optional signature word") {
        const fs::path out = work / "dd-nosig.lexe";
        build_with_data_descriptors(blobs, {"payload/data.txt"}, false, out);
        CHECK(verify_ok(out));
    }
}

} // TEST_SUITE

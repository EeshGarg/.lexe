// verify module tests (ARCHITECTURE.md #Tests): a good package passes every
// FORMAT-0.1 §6 stage; each pipeline stage fails on the matching tamper —
// corrupt zip structure, invalid manifest field, bad key string, flipped byte
// in lexe.json after signing, flipped byte in hashes.json, flipped byte in a
// payload file, added uncovered entry, removed covered entry — with all
// earlier stages green and no later stage recorded.
// Every test case constructs lexe::test::TempLexeHome first.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/verify.hpp"

#include <miniz/miniz.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using lexe::VerificationReport;
using lexe::test::TempLexeHome;

// FORMAT-0.1 §6 normative stage order (names from verify.hpp).
const std::array<std::string, 7> kStageOrder = {
    "structure",         "manifest", "key",   "manifest-signature",
    "payload-signature", "hashes",   "compatibility"};

/// Assert the report failed exactly at `stage_name`: every earlier stage is
/// present, correctly named and green; the failing stage is last (stages
/// after the first failure are absent per verify.hpp); detail is non-empty.
void expect_failure_at(const VerificationReport& report,
                       const std::string& stage_name) {
    const auto it =
        std::find(kStageOrder.begin(), kStageOrder.end(), stage_name);
    REQUIRE(it != kStageOrder.end());
    const std::size_t index =
        static_cast<std::size_t>(it - kStageOrder.begin());

    REQUIRE(report.stages.size() == index + 1);
    for (std::size_t i = 0; i < index; ++i) {
        CAPTURE(i);
        CHECK(report.stages[i].name == kStageOrder[i]);
        CHECK(report.stages[i].ok);
    }
    CHECK(report.stages[index].name == stage_name);
    CHECK_FALSE(report.stages[index].ok);
    CHECK_FALSE(report.stages[index].detail.empty());

    CHECK_FALSE(report.ok());
    REQUIRE(report.first_failure() != nullptr);
    CHECK(report.first_failure()->name == stage_name);
}

/// Detail text of the failing stage (empty when the report passed).
std::string failure_detail(const VerificationReport& report) {
    const lexe::VerificationStage* failure = report.first_failure();
    return failure == nullptr ? std::string() : failure->detail;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// ---------------------------------------------------------------- raw zip IO
// Minimal raw archive rewriting (miniz, memory-backed) so tests can add and
// remove whole entries — tamper_entry (helpers.hpp) only mutates content.

struct RawEntry {
    std::string name;
    std::vector<std::uint8_t> bytes;
};

std::vector<RawEntry> read_raw_entries(const fs::path& zip_path) {
    const std::vector<std::uint8_t> archive = lexe::util::slurp(zip_path);
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    REQUIRE(mz_zip_reader_init_mem(&zip, archive.data(), archive.size(), 0));
    std::vector<RawEntry> out;
    const mz_uint count = mz_zip_reader_get_num_files(&zip);
    for (mz_uint i = 0; i < count; ++i) {
        mz_zip_archive_file_stat st;
        std::memset(&st, 0, sizeof(st));
        REQUIRE(mz_zip_reader_file_stat(&zip, i, &st));
        if (mz_zip_reader_is_file_a_directory(&zip, i)) continue;
        RawEntry e;
        e.name = st.m_filename;
        if (st.m_uncomp_size > 0) {
            std::size_t size = 0;
            void* p = mz_zip_reader_extract_to_heap(&zip, i, &size, 0);
            REQUIRE(p != nullptr);
            e.bytes.assign(static_cast<std::uint8_t*>(p),
                           static_cast<std::uint8_t*>(p) + size);
            mz_free(p);
        }
        out.push_back(std::move(e));
    }
    mz_zip_reader_end(&zip);
    return out;
}

void write_raw_zip(const fs::path& zip_path,
                   const std::vector<RawEntry>& entries) {
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    REQUIRE(mz_zip_writer_init_heap(&zip, 0, 0));
    for (const RawEntry& e : entries) {
        const void* data = e.bytes.empty()
                               ? static_cast<const void*>("")
                               : static_cast<const void*>(e.bytes.data());
        REQUIRE(mz_zip_writer_add_mem(&zip, e.name.c_str(), data,
                                      e.bytes.size(), MZ_BEST_COMPRESSION));
    }
    void* buf = nullptr;
    std::size_t size = 0;
    REQUIRE(mz_zip_writer_finalize_heap_archive(&zip, &buf, &size));
    lexe::util::spit(zip_path, static_cast<const std::uint8_t*>(buf), size);
    mz_zip_writer_end(&zip);
}

/// Append a brand-new entry to the archive (uncovered by hashes.json).
void add_raw_entry(const fs::path& zip_path, const std::string& name,
                   const std::string& content) {
    std::vector<RawEntry> entries = read_raw_entries(zip_path);
    entries.push_back(
        {name, std::vector<std::uint8_t>(content.begin(), content.end())});
    write_raw_zip(zip_path, entries);
}

/// Remove one entry from the archive (leaving hashes.json covering it).
void remove_raw_entry(const fs::path& zip_path, const std::string& name) {
    const std::vector<RawEntry> before = read_raw_entries(zip_path);
    std::vector<RawEntry> after;
    for (const RawEntry& e : before) {
        if (e.name != name) after.push_back(e);
    }
    REQUIRE(after.size() == before.size() - 1);
    write_raw_zip(zip_path, after);
}

/// In-place textual replacement inside one entry's bytes (any lengths).
void replace_in_entry(const fs::path& zip_path, const std::string& entry,
                      const std::string& find, const std::string& replace) {
    lexe::test::tamper_entry(
        zip_path, entry, [&](std::vector<std::uint8_t>& bytes) {
            std::string text(bytes.begin(), bytes.end());
            const std::size_t pos = text.find(find);
            REQUIRE(pos != std::string::npos);
            text.replace(pos, find.size(), replace);
            bytes.assign(text.begin(), text.end());
        });
}

/// Replace an entry's bytes wholesale.
void set_entry_bytes(const fs::path& zip_path, const std::string& entry,
                     const std::vector<std::uint8_t>& new_bytes) {
    lexe::test::tamper_entry(zip_path, entry,
                             [&](std::vector<std::uint8_t>& bytes) {
                                 bytes = new_bytes;
                             });
}

/// Rewrite metadata/hashes.json through `mutate` and RE-SIGN it with `key`,
/// so stages 1–5 stay green and only the hashes stage sees the change.
void tamper_hashes_resigned(
    const fs::path& pkg, const lexe::crypto::KeyPair& key,
    const std::function<void(nlohmann::json&)>& mutate) {
    const std::vector<std::uint8_t> old_bytes =
        lexe::PackageReader(pkg).read_entry("metadata/hashes.json");
    nlohmann::json doc =
        nlohmann::json::parse(old_bytes.begin(), old_bytes.end());
    mutate(doc);
    const std::string text = doc.dump(2);
    const std::vector<std::uint8_t> new_bytes(text.begin(), text.end());
    const lexe::crypto::Signature sig = lexe::crypto::sign(new_bytes, key);
    set_entry_bytes(pkg, "metadata/hashes.json", new_bytes);
    set_entry_bytes(pkg, "signatures/payload.sig",
                    std::vector<std::uint8_t>(sig.begin(), sig.end()));
}

/// Build a package whose manifest carries `public_key_string` verbatim,
/// signed by `signer` (make_test_package would overwrite the key string, so
/// bad-key packages are assembled by hand).
fs::path make_package_with_key_string(const fs::path& work_dir,
                                      const lexe::crypto::KeyPair& signer,
                                      const std::string& public_key_string) {
    lexe::test::TestAppSpec spec;
    spec.public_key = public_key_string;
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(work_dir / "badkey-tree", spec);
    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path out = work_dir / "badkey.lexe";
    lexe::PackageWriter::write(inputs, signer, out);
    return out;
}

/// Build a signed package whose manifest lists exactly `architectures`.
fs::path make_package_with_architectures(
    const fs::path& work_dir, const lexe::crypto::KeyPair& key,
    const std::vector<std::string>& architectures) {
    lexe::test::TestAppSpec spec;
    spec.public_key = lexe::test::encode_public_key_str(key.public_key);
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(work_dir / "arch-tree", spec);
    nlohmann::json manifest = nlohmann::json::parse(
        lexe::util::slurp_text(tree.manifest_file));
    manifest["architectures"] = architectures;
    lexe::util::spit(tree.manifest_file,
                     std::string_view(manifest.dump(2) + "\n"));
    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path out = work_dir / "arch-app.lexe";
    lexe::PackageWriter::write(inputs, key, out);
    return out;
}

} // namespace

TEST_SUITE("verify") {

// ===================================================================
// The good path
// ===================================================================

TEST_CASE("good package passes all six stages in normative order") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    const VerificationReport report = lexe::verify_package(pkg);
    CHECK(report.ok());
    CHECK(report.first_failure() == nullptr);
    REQUIRE(report.stages.size() == 6); // no compatibility stage by default
    for (std::size_t i = 0; i < report.stages.size(); ++i) {
        CAPTURE(i);
        CHECK(report.stages[i].name == kStageOrder[i]);
        CHECK(report.stages[i].ok);
        CHECK_FALSE(report.stages[i].detail.empty());
    }
}

TEST_CASE("good package passes all seven stages with architecture check") {
    TempLexeHome home;
    // The test package lists both recognised architectures, so this holds on
    // any supported host.
    const std::string host = lexe::host_architecture();
    REQUIRE((host == "x86_64" || host == "aarch64"));

    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    const VerificationReport report =
        lexe::verify_package(pkg, /*check_architecture=*/true);
    CHECK(report.ok());
    REQUIRE(report.stages.size() == 7);
    for (std::size_t i = 0; i < report.stages.size(); ++i) {
        CAPTURE(i);
        CHECK(report.stages[i].name == kStageOrder[i]);
        CHECK(report.stages[i].ok);
    }
    CHECK(contains(report.stages[6].detail, host));
}

TEST_CASE("verify_package_or_throw returns the parsed manifest") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::TestAppSpec spec;
    spec.id = "com.example.verifyme";
    spec.version = "2.3.4";
    const fs::path pkg = lexe::test::make_test_package(home.path(), key, spec);

    const lexe::Manifest m = lexe::verify_package_or_throw(pkg);
    CHECK(m.id == "com.example.verifyme");
    CHECK(m.version == "2.3.4");
    CHECK(m.name == "Hello App");
    CHECK(m.publisher_public_key ==
          lexe::test::encode_public_key_str(key.public_key));
    CHECK(m.install_mode == "bundled");

    // With the architecture check as well (install/update path).
    const lexe::Manifest m2 =
        lexe::verify_package_or_throw(pkg, /*check_architecture=*/true);
    CHECK(m2.id == m.id);
}

// ===================================================================
// Stage 1 — structure (§2)
// ===================================================================

TEST_CASE("structure: corrupt zip structure fails at stage 1") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    SUBCASE("file is not a zip archive at all") {
        lexe::util::spit(pkg, std::string_view("garbage, not a PK archive"));
        expect_failure_at(lexe::verify_package(pkg), "structure");
    }
    SUBCASE("file is empty") {
        lexe::util::spit(pkg, std::vector<std::uint8_t>{});
        expect_failure_at(lexe::verify_package(pkg), "structure");
    }
    SUBCASE("archive is truncated (central directory destroyed)") {
        std::vector<std::uint8_t> bytes = lexe::util::slurp(pkg);
        REQUIRE(bytes.size() > 64);
        bytes.resize(bytes.size() / 2);
        lexe::util::spit(pkg, bytes);
        expect_failure_at(lexe::verify_package(pkg), "structure");
    }
    SUBCASE("entry outside the allowed top-level set") {
        add_raw_entry(pkg, "evil/x.txt", "boo");
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "structure");
        CHECK(contains(failure_detail(report), "evil"));
    }
    SUBCASE("path traversal entry") {
        add_raw_entry(pkg, "payload/../../evil", "boo");
        expect_failure_at(lexe::verify_package(pkg), "structure");
    }
    SUBCASE("required entry missing: signatures/manifest.sig") {
        remove_raw_entry(pkg, "signatures/manifest.sig");
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "structure");
        CHECK(contains(failure_detail(report), "signatures/manifest.sig"));
    }
    SUBCASE("required entry missing: metadata/hashes.json") {
        remove_raw_entry(pkg, "metadata/hashes.json");
        expect_failure_at(lexe::verify_package(pkg), "structure");
    }
    SUBCASE("required entry missing: lexe.json") {
        remove_raw_entry(pkg, "lexe.json");
        expect_failure_at(lexe::verify_package(pkg), "structure");
    }
}

TEST_CASE("structure: missing package file is reported, not thrown") {
    TempLexeHome home;
    const fs::path absent = home.path() / "no-such-package.lexe";
    VerificationReport report;
    CHECK_NOTHROW(report = lexe::verify_package(absent));
    expect_failure_at(report, "structure");
}

// ===================================================================
// Stage 2 — manifest (§5)
// ===================================================================

TEST_CASE("manifest: invalid manifest field fails at stage 2") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    SUBCASE("unsupported lexeVersion") {
        replace_in_entry(pkg, "lexe.json", "\"lexeVersion\": \"0.1\"",
                         "\"lexeVersion\": \"9.9\"");
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "manifest");
        CHECK(contains(failure_detail(report), "lexeVersion"));
    }
    SUBCASE("lexe.json is not valid JSON") {
        lexe::test::tamper_entry(pkg, "lexe.json",
                                 [](std::vector<std::uint8_t>& bytes) {
                                     REQUIRE(!bytes.empty());
                                     bytes[0] = 'X'; // clobber the opening '{'
                                 });
        expect_failure_at(lexe::verify_package(pkg), "manifest");
    }
    SUBCASE("unsupported install.mode") {
        replace_in_entry(pkg, "lexe.json", "\"mode\": \"bundled\"",
                         "\"mode\": \"network\"");
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "manifest");
        CHECK(contains(failure_detail(report), "unsupported in 0.1"));
    }
}

TEST_CASE("manifest: §5-invalid manifest fails at stage 2 even when its "
          "signatures are genuine") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();

    // Build the tree, strip the required "name" field BEFORE packing: the
    // package carries perfectly valid signatures over an invalid manifest.
    lexe::test::TestAppSpec spec;
    spec.public_key = lexe::test::encode_public_key_str(key.public_key);
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(home.path() / "tree", spec);
    nlohmann::json manifest =
        nlohmann::json::parse(lexe::util::slurp_text(tree.manifest_file));
    manifest.erase("name");
    lexe::util::spit(tree.manifest_file,
                     std::string_view(manifest.dump(2) + "\n"));

    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path pkg = home.path() / "noname.lexe";
    lexe::PackageWriter::write(inputs, key, pkg);

    const VerificationReport report = lexe::verify_package(pkg);
    expect_failure_at(report, "manifest");
    CHECK(contains(failure_detail(report), "name"));
}

// ===================================================================
// Stage 3 — key decode (§4)
// ===================================================================

TEST_CASE("key: bad publisher key string fails at stage 3") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();

    SUBCASE("wrong prefix (tampered after signing)") {
        const fs::path pkg = lexe::test::make_test_package(home.path(), key);
        // Same-length corruption of the "ed25519:" prefix. §5 still holds
        // (non-empty string), so this must get past the manifest stage and
        // die at key decode — before any signature check.
        replace_in_entry(pkg, "lexe.json", "ed25519:", "ed25519;");
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "key");
        CHECK(contains(failure_detail(report), "prefix"));
    }
    SUBCASE("bad base64 after the prefix") {
        const fs::path pkg = make_package_with_key_string(
            home.path(), key, "ed25519:!!!this is not base64!!!");
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "key");
    }
    SUBCASE("decoded length is not 32 bytes") {
        const fs::path pkg = make_package_with_key_string(
            home.path(), key, "ed25519:AAAA"); // decodes to 3 bytes
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "key");
        CHECK(contains(failure_detail(report), "32"));
    }
}

// ===================================================================
// Stage 4 — manifest signature (§4, exact stored bytes)
// ===================================================================

TEST_CASE("manifest-signature: flipped byte in lexe.json after signing "
          "fails at stage 4") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    // "Hello App" -> "Hella App": still a §5-valid manifest with a decodable
    // key, but no longer the signed bytes.
    replace_in_entry(pkg, "lexe.json", "Hello App", "Hella App");
    const VerificationReport report = lexe::verify_package(pkg);
    expect_failure_at(report, "manifest-signature");
    CHECK(contains(failure_detail(report), "manifest.sig"));
}

TEST_CASE("manifest-signature: package signed by a key other than the "
          "declared publisher key fails at stage 4") {
    TempLexeHome home;
    const lexe::crypto::KeyPair signer = lexe::test::make_keypair();
    const lexe::crypto::KeyPair declared = lexe::test::make_keypair();

    lexe::test::TestAppSpec spec;
    spec.public_key = lexe::test::encode_public_key_str(declared.public_key);
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(home.path() / "tree", spec);
    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path pkg = home.path() / "wrong-signer.lexe";
    lexe::PackageWriter::write(inputs, signer, pkg);

    expect_failure_at(lexe::verify_package(pkg), "manifest-signature");
}

TEST_CASE("manifest-signature: signature entry with a wrong size fails at "
          "stage 4") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    lexe::test::tamper_entry(pkg, "signatures/manifest.sig",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE(bytes.size() == 64);
                                 bytes.resize(10);
                             });
    const VerificationReport report = lexe::verify_package(pkg);
    expect_failure_at(report, "manifest-signature");
    CHECK(contains(failure_detail(report), "64"));
}

TEST_CASE("manifest-signature: swapped signature files fail at stage 4") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    const std::vector<std::uint8_t> payload_sig =
        lexe::PackageReader(pkg).read_entry("signatures/payload.sig");
    set_entry_bytes(pkg, "signatures/manifest.sig", payload_sig);
    expect_failure_at(lexe::verify_package(pkg), "manifest-signature");
}

// ===================================================================
// Stage 5 — payload signature (§4, exact stored bytes)
// ===================================================================

TEST_CASE("payload-signature: flipped byte in hashes.json fails at stage 5") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    // Any byte change to the stored hashes.json invalidates payload.sig —
    // and it must fail THERE (stage 5), before the hash content is looked at.
    lexe::test::tamper_entry(pkg, "metadata/hashes.json",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE(!bytes.empty());
                                 bytes[0] ^= 0x01;
                             });
    const VerificationReport report = lexe::verify_package(pkg);
    expect_failure_at(report, "payload-signature");
    CHECK(contains(failure_detail(report), "payload.sig"));
}

TEST_CASE("payload-signature: truncated payload.sig fails at stage 5 with "
          "stage 4 green") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    lexe::test::tamper_entry(pkg, "signatures/payload.sig",
                             [](std::vector<std::uint8_t>& bytes) {
                                 bytes.resize(63);
                             });
    expect_failure_at(lexe::verify_package(pkg), "payload-signature");
}

// ===================================================================
// Stage 6 — hashes (§3, set equality both directions + digests)
// ===================================================================

TEST_CASE("hashes: flipped byte in a payload file fails at stage 6") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    lexe::test::tamper_entry(pkg, "payload/data.txt",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE(!bytes.empty());
                                 bytes[0] ^= 0xFF;
                             });
    const VerificationReport report = lexe::verify_package(pkg);
    expect_failure_at(report, "hashes");
    CHECK(contains(failure_detail(report), "payload/data.txt"));
    CHECK(contains(failure_detail(report), "mismatch"));
}

TEST_CASE("hashes: flipped byte in a nested payload file fails at stage 6") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    lexe::test::tamper_entry(pkg, "payload/bin/hello.sh",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE(!bytes.empty());
                                 bytes.back() ^= 0x20;
                             });
    const VerificationReport report = lexe::verify_package(pkg);
    expect_failure_at(report, "hashes");
    CHECK(contains(failure_detail(report), "payload/bin/hello.sh"));
}

TEST_CASE("hashes: added uncovered entry fails at stage 6") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    SUBCASE("under payload/") {
        add_raw_entry(pkg, "payload/extra.bin", "smuggled bytes");
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "hashes");
        CHECK(contains(failure_detail(report), "payload/extra.bin"));
        CHECK(contains(failure_detail(report), "not covered"));
    }
    SUBCASE("under scripts/ (reserved, still must be covered)") {
        add_raw_entry(pkg, "scripts/health-check", "#!/bin/sh\n");
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "hashes");
        CHECK(contains(failure_detail(report), "scripts/health-check"));
    }
    SUBCASE("under icons/") {
        add_raw_entry(pkg, "icons/512.png", "not really a png");
        expect_failure_at(lexe::verify_package(pkg), "hashes");
    }
}

TEST_CASE("hashes: removed covered entry fails at stage 6") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    // Other payload entries remain, so §2 structure still holds; only the
    // §3 set equality (files -> archive direction) is broken.
    remove_raw_entry(pkg, "payload/data.txt");
    const VerificationReport report = lexe::verify_package(pkg);
    expect_failure_at(report, "hashes");
    CHECK(contains(failure_detail(report), "payload/data.txt"));
    CHECK(contains(failure_detail(report), "missing from archive"));
}

TEST_CASE("hashes: properly re-signed hashes.json corruption still fails at "
          "stage 6 with both signature stages green") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    SUBCASE("wrong algorithm") {
        tamper_hashes_resigned(pkg, key, [](nlohmann::json& doc) {
            doc["algorithm"] = "sha1";
        });
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "hashes");
        CHECK(contains(failure_detail(report), "sha256"));
    }
    SUBCASE("wrong digest value") {
        tamper_hashes_resigned(pkg, key, [](nlohmann::json& doc) {
            doc["files"]["payload/data.txt"] = std::string(64, '0');
        });
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "hashes");
        CHECK(contains(failure_detail(report), "payload/data.txt"));
    }
    SUBCASE("files illegally covering lexe.json") {
        tamper_hashes_resigned(pkg, key, [](nlohmann::json& doc) {
            doc["files"]["lexe.json"] = std::string(64, 'a');
        });
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "hashes");
        CHECK(contains(failure_detail(report), "lexe.json"));
    }
    SUBCASE("files entry for a non-existent archive path") {
        tamper_hashes_resigned(pkg, key, [](nlohmann::json& doc) {
            doc["files"]["payload/ghost.txt"] = std::string(64, 'b');
        });
        const VerificationReport report = lexe::verify_package(pkg);
        expect_failure_at(report, "hashes");
        CHECK(contains(failure_detail(report), "payload/ghost.txt"));
    }
    SUBCASE("digest value that is not a string") {
        tamper_hashes_resigned(pkg, key, [](nlohmann::json& doc) {
            doc["files"]["payload/data.txt"] = 12345;
        });
        expect_failure_at(lexe::verify_package(pkg), "hashes");
    }
}

// ===================================================================
// Stage 7 — compatibility (§6.7, install/update only)
// ===================================================================

TEST_CASE("host_architecture reports a recognised manifest value") {
    TempLexeHome home;
    const std::string host = lexe::host_architecture();
    CHECK((host == "x86_64" || host == "aarch64"));
}

TEST_CASE("compatibility: unsupported architecture fails at stage 7 only "
          "when requested") {
    TempLexeHome home;
    const std::string host = lexe::host_architecture();
    REQUIRE((host == "x86_64" || host == "aarch64"));
    const std::string other = host == "x86_64" ? "aarch64" : "x86_64";

    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg =
        make_package_with_architectures(home.path(), key, {other});

    // `lexe verify` (no architecture check): six green stages, no seventh.
    const VerificationReport plain = lexe::verify_package(pkg);
    CHECK(plain.ok());
    CHECK(plain.stages.size() == 6);

    // install/update path: first six green, compatibility fails.
    const VerificationReport checked =
        lexe::verify_package(pkg, /*check_architecture=*/true);
    expect_failure_at(checked, "compatibility");
    CHECK(contains(failure_detail(checked), host));
    CHECK(contains(failure_detail(checked), other));
}

TEST_CASE("compatibility: package listing only the host architecture passes") {
    TempLexeHome home;
    const std::string host = lexe::host_architecture();
    REQUIRE((host == "x86_64" || host == "aarch64"));

    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg =
        make_package_with_architectures(home.path(), key, {host});
    const VerificationReport report =
        lexe::verify_package(pkg, /*check_architecture=*/true);
    CHECK(report.ok());
    CHECK(report.stages.size() == 7);
}

// ===================================================================
// verify_package_or_throw failure behaviour
// ===================================================================

TEST_CASE("verify_package_or_throw throws VerificationError naming the "
          "failed stage") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);
    lexe::test::tamper_entry(pkg, "payload/data.txt",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE(!bytes.empty());
                                 bytes[0] ^= 0xFF;
                             });

    try {
        (void)lexe::verify_package_or_throw(pkg);
        FAIL("expected VerificationError");
    } catch (const lexe::VerificationError& e) {
        CHECK(contains(e.what(), "hashes"));
        CHECK(contains(e.what(), "payload/data.txt"));
    }
}

TEST_CASE("verify_package_or_throw throws VerificationError for a missing "
          "file") {
    TempLexeHome home;
    CHECK_THROWS_AS(
        (void)lexe::verify_package_or_throw(home.path() / "absent.lexe"),
        lexe::VerificationError);
}

} // TEST_SUITE("verify")

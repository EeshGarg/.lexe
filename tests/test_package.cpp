// package module tests (ARCHITECTURE.md #Tests): determinism (pack twice ->
// byte-identical), FORMAT-0.1 §2 malicious-path corpus, round-trip
// pack -> read -> extract -> compare, duplicate entries, required-entry
// missing, store-vs-deflate boundary, hashes.json (§3) and signatures (§4).
// Every test case constructs lexe::test::TempLexeHome first.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include <ed25519/ed25519.h>
#include <miniz/miniz.h>
#include <nlohmann/json.hpp>
#include <picosha2/picosha2.h>

#include <array>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using lexe::test::TempLexeHome;

// -------------------------------------------------------------- raw zip IO

struct RawEntry {
    std::string name;
    std::vector<std::uint8_t> bytes;
};

std::vector<std::uint8_t> text_bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

/// All file entries of a zip in archive (index) order, decompressed.
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

/// Write a zip with exactly these entries in the given order (no path
/// validation — this is how the tests build malicious archives).
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

/// Replace every occurrence of `find` with same-length `replace` in a file
/// (used to smuggle names miniz's writer refuses: leading '/', NUL bytes).
void patch_bytes(const fs::path& file, const std::string& find,
                 const std::string& replace) {
    REQUIRE(find.size() == replace.size());
    const std::vector<std::uint8_t> bytes = lexe::util::slurp(file);
    std::string data(bytes.begin(), bytes.end());
    std::size_t count = 0;
    std::size_t pos = 0;
    while ((pos = data.find(find, pos)) != std::string::npos) {
        data.replace(pos, find.size(), replace);
        pos += replace.size();
        ++count;
    }
    REQUIRE(count > 0);
    lexe::util::spit(file, std::string_view(data));
}

/// Set the central-directory external attributes of one entry (used to mark
/// an entry as a Unix symlink, S_IFLNK in the high 16 bits).
void set_entry_external_attr(const fs::path& file, const std::string& name,
                             std::uint32_t attr) {
    std::vector<std::uint8_t> bytes = lexe::util::slurp(file);
    bool found = false;
    for (std::size_t i = 0; i + 46 <= bytes.size(); ++i) {
        if (bytes[i] != 0x50 || bytes[i + 1] != 0x4B || bytes[i + 2] != 0x01 ||
            bytes[i + 3] != 0x02) {
            continue; // not a central directory file header
        }
        const std::size_t name_len =
            static_cast<std::size_t>(bytes[i + 28]) |
            (static_cast<std::size_t>(bytes[i + 29]) << 8);
        if (i + 46 + name_len > bytes.size()) continue;
        const std::string entry_name(
            reinterpret_cast<const char*>(&bytes[i + 46]), name_len);
        if (entry_name != name) continue;
        bytes[i + 38] = static_cast<std::uint8_t>(attr & 0xFFu);
        bytes[i + 39] = static_cast<std::uint8_t>((attr >> 8) & 0xFFu);
        bytes[i + 40] = static_cast<std::uint8_t>((attr >> 16) & 0xFFu);
        bytes[i + 41] = static_cast<std::uint8_t>((attr >> 24) & 0xFFu);
        found = true;
    }
    REQUIRE(found);
    lexe::util::spit(file, bytes);
}

// -------------------------------------------------------------- misc

std::string sha256_hex_ref(const std::vector<std::uint8_t>& bytes) {
    std::array<unsigned char, picosha2::k_digest_size> digest{};
    picosha2::hash256(bytes.begin(), bytes.end(), digest.begin(),
                      digest.end());
    return lexe::util::hex_encode(digest.data(), digest.size());
}

/// relative-path -> file-bytes map of every regular file under `dir`.
std::map<std::string, std::vector<std::uint8_t>>
snapshot_tree(const fs::path& dir) {
    std::map<std::string, std::vector<std::uint8_t>> out;
    for (fs::recursive_directory_iterator it(dir), end; it != end; ++it) {
        if (!it->is_regular_file()) continue;
        const std::string rel =
            it->path().lexically_relative(dir).generic_string();
        out[rel] = lexe::util::slurp(it->path());
    }
    return out;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.rfind(prefix, 0) == 0;
}

} // namespace

TEST_SUITE("package") {

// ===================================================================
// PackageWriter — FORMAT-0.1 §1 determinism and container discipline
// ===================================================================

TEST_CASE("determinism: packing the same tree twice is byte-identical") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(home.path() / "tree");

    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;

    const fs::path out1 = home.path() / "a.lexe";
    const fs::path out2 = home.path() / "b.lexe";
    lexe::PackageWriter::write(inputs, key, out1);
    lexe::PackageWriter::write(inputs, key, out2);

    const auto bytes1 = lexe::util::slurp(out1);
    const auto bytes2 = lexe::util::slurp(out2);
    CHECK(bytes1.size() > 0);
    CHECK(bytes1 == bytes2);

    // Rewriting a payload file with identical content (fresh mtime) must not
    // change the archive either — timestamps are zeroed (MINIZ_NO_TIME).
    const fs::path data_file = tree.payload_dir / "data.txt";
    const auto data = lexe::util::slurp(data_file);
    lexe::util::spit(data_file, data);
    const fs::path out3 = home.path() / "c.lexe";
    lexe::PackageWriter::write(inputs, key, out3);
    CHECK(lexe::util::slurp(out3) == bytes1);
}

TEST_CASE("archive entries are stored in lexicographic byte order") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    const std::vector<RawEntry> raw = read_raw_entries(pkg);
    REQUIRE(raw.size() > 2);
    for (std::size_t i = 1; i < raw.size(); ++i) {
        CAPTURE(raw[i - 1].name);
        CAPTURE(raw[i].name);
        CHECK(raw[i - 1].name < raw[i].name);
    }
}

TEST_CASE("store-vs-deflate boundary: <64 bytes STORE, >=64 bytes DEFLATE") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(home.path() / "tree");
    lexe::util::spit(tree.payload_dir / "a63.bin", std::string(63, 'a'));
    lexe::util::spit(tree.payload_dir / "b64.bin", std::string(64, 'b'));

    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path pkg = home.path() / "app.lexe";
    lexe::PackageWriter::write(inputs, key, pkg);

    const std::vector<std::uint8_t> archive = lexe::util::slurp(pkg);
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    REQUIRE(mz_zip_reader_init_mem(&zip, archive.data(), archive.size(), 0));
    const auto method_of = [&](const char* name) -> int {
        const int idx = mz_zip_reader_locate_file(&zip, name, nullptr, 0);
        REQUIRE(idx >= 0);
        mz_zip_archive_file_stat st;
        std::memset(&st, 0, sizeof(st));
        REQUIRE(mz_zip_reader_file_stat(&zip, static_cast<mz_uint>(idx), &st));
        return static_cast<int>(st.m_method);
    };
    CHECK(method_of("payload/a63.bin") == 0);      // STORE
    CHECK(method_of("payload/b64.bin") == 8);      // DEFLATE
    CHECK(method_of("lexe.json") == 8);            // well above the boundary
    // raw 64-byte signatures sit exactly on the boundary -> DEFLATE
    CHECK(method_of("signatures/manifest.sig") == 8);
    CHECK(method_of("signatures/payload.sig") == 8);
    mz_zip_reader_end(&zip);
}

TEST_CASE("writer includes optional icons/ and metadata/ trees") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(home.path() / "tree");
    lexe::util::spit(home.path() / "icons" / "64.png",
                     std::string(80, 'p')); // fake but stable bytes
    lexe::util::spit(home.path() / "meta" / "description.md",
                     std::string_view("# Hello App\n"));

    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    inputs.icons_dir = home.path() / "icons";
    inputs.metadata_dir = home.path() / "meta";
    const fs::path pkg = home.path() / "app.lexe";
    lexe::PackageWriter::write(inputs, key, pkg);

    const lexe::PackageReader reader(pkg);
    CHECK(reader.has_entry("icons/64.png"));
    CHECK(reader.has_entry("metadata/description.md"));

    // Both must be covered by hashes.json (§3).
    const auto hashes_bytes = reader.read_entry("metadata/hashes.json");
    const nlohmann::json j =
        nlohmann::json::parse(hashes_bytes.begin(), hashes_bytes.end());
    CHECK(j.at("files").contains("icons/64.png"));
    CHECK(j.at("files").contains("metadata/description.md"));
}

TEST_CASE("writer rejects invalid inputs") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(home.path() / "tree");
    const fs::path out = home.path() / "out.lexe";

    SUBCASE("missing payload directory") {
        lexe::PackageWriter::Inputs inputs;
        inputs.payload_dir = home.path() / "no-such-dir";
        inputs.manifest_file = tree.manifest_file;
        CHECK_THROWS_AS(lexe::PackageWriter::write(inputs, key, out),
                        lexe::Error);
    }
    SUBCASE("missing manifest file") {
        lexe::PackageWriter::Inputs inputs;
        inputs.payload_dir = tree.payload_dir;
        inputs.manifest_file = home.path() / "no-such.json";
        CHECK_THROWS_AS(lexe::PackageWriter::write(inputs, key, out),
                        lexe::Error);
    }
    SUBCASE("empty payload directory") {
        const fs::path empty_dir = home.path() / "empty";
        fs::create_directories(empty_dir);
        lexe::PackageWriter::Inputs inputs;
        inputs.payload_dir = empty_dir;
        inputs.manifest_file = tree.manifest_file;
        CHECK_THROWS_AS(lexe::PackageWriter::write(inputs, key, out),
                        lexe::Error);
    }
    SUBCASE("manifest that is not valid JSON") {
        const fs::path bad_manifest = home.path() / "bad.json";
        lexe::util::spit(bad_manifest, std::string_view("{not json"));
        lexe::PackageWriter::Inputs inputs;
        inputs.payload_dir = tree.payload_dir;
        inputs.manifest_file = bad_manifest;
        CHECK_THROWS_AS(lexe::PackageWriter::write(inputs, key, out),
                        lexe::Error);
    }
    SUBCASE("metadata directory smuggling a hashes.json") {
        const fs::path meta = home.path() / "meta";
        lexe::util::spit(meta / "hashes.json", std::string_view("{}"));
        lexe::PackageWriter::Inputs inputs;
        inputs.payload_dir = tree.payload_dir;
        inputs.manifest_file = tree.manifest_file;
        inputs.metadata_dir = meta;
        CHECK_THROWS_AS(lexe::PackageWriter::write(inputs, key, out),
                        lexe::Error);
    }
}

// ===================================================================
// hashes.json (§3) and signatures (§4)
// ===================================================================

TEST_CASE("hashes.json covers exactly the right entries with correct digests") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);
    const lexe::PackageReader reader(pkg);

    const auto hashes_bytes = reader.read_entry("metadata/hashes.json");
    const nlohmann::json j =
        nlohmann::json::parse(hashes_bytes.begin(), hashes_bytes.end());
    CHECK(j.at("algorithm").get<std::string>() == "sha256");

    // Set equality in both directions (§3): every archive entry except
    // lexe.json, hashes.json itself and signatures/* — and nothing else.
    std::set<std::string> expected;
    for (const lexe::PackageEntry& e : reader.entries()) {
        if (e.path == "lexe.json") continue;
        if (e.path == "metadata/hashes.json") continue;
        if (starts_with(e.path, "signatures/")) continue;
        expected.insert(e.path);
    }
    std::set<std::string> covered;
    for (const auto& [path, digest] : j.at("files").items()) {
        covered.insert(path);
        CAPTURE(path);
        CHECK(digest.get<std::string>() ==
              sha256_hex_ref(reader.read_entry(path)));
    }
    CHECK(covered == expected);
}

TEST_CASE("signatures are raw 64-byte Ed25519 over exact entry bytes") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);
    const lexe::PackageReader reader(pkg);

    const auto manifest_bytes = reader.read_entry("lexe.json");
    const auto hashes_bytes = reader.read_entry("metadata/hashes.json");
    const auto manifest_sig = reader.read_entry("signatures/manifest.sig");
    const auto payload_sig = reader.read_entry("signatures/payload.sig");
    REQUIRE(manifest_sig.size() == 64);
    REQUIRE(payload_sig.size() == 64);

    CHECK(ed25519_verify(manifest_sig.data(), manifest_bytes.data(),
                         manifest_bytes.size(), key.public_key.data()) == 1);
    CHECK(ed25519_verify(payload_sig.data(), hashes_bytes.data(),
                         hashes_bytes.size(), key.public_key.data()) == 1);

    // Signature must fail over different bytes / with a different key.
    std::vector<std::uint8_t> tampered = manifest_bytes;
    tampered[0] ^= 0x01;
    CHECK(ed25519_verify(manifest_sig.data(), tampered.data(), tampered.size(),
                         key.public_key.data()) == 0);
    const lexe::crypto::KeyPair other = lexe::test::make_keypair();
    CHECK(ed25519_verify(manifest_sig.data(), manifest_bytes.data(),
                         manifest_bytes.size(), other.public_key.data()) == 0);
}

// ===================================================================
// PackageReader — reading, round-trip, extraction
// ===================================================================

TEST_CASE("reader lists sorted entries and reads exact bytes") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::TestAppSpec spec;
    const fs::path pkg = lexe::test::make_test_package(home.path(), key, spec);
    const lexe::PackageReader reader(pkg);

    CHECK(reader.file() == pkg);

    const std::vector<lexe::PackageEntry> entries = reader.entries();
    REQUIRE(entries.size() >= 6); // manifest, hashes, 2 sigs, 3 payload files
    for (std::size_t i = 1; i < entries.size(); ++i) {
        CHECK(entries[i - 1].path < entries[i].path);
    }

    CHECK(reader.has_entry("lexe.json"));
    CHECK(reader.has_entry("payload/data.txt"));
    CHECK(reader.has_entry("payload/bin/hello.sh"));
    CHECK_FALSE(reader.has_entry("payload/nope.txt"));
    CHECK_FALSE(reader.has_entry("payload"));

    // Byte-exact storage of lexe.json (the tree the helper packed from).
    const fs::path tree_manifest = home.path() /
                                   ("tree-" + spec.id + "-" + spec.version) /
                                   "lexe.json";
    CHECK(reader.read_entry("lexe.json") == lexe::util::slurp(tree_manifest));

    // Sizes reported match the decompressed bytes.
    for (const lexe::PackageEntry& e : entries) {
        CAPTURE(e.path);
        CHECK(reader.read_entry(e.path).size() == e.uncompressed_size);
    }

    CHECK_THROWS_AS((void)reader.read_entry("payload/nope.txt"),
                    lexe::NotFoundError);
}

TEST_CASE("round-trip: pack -> read -> extract payload -> identical tree") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(home.path() / "tree");
    // Edge cases: an empty file and a nested deflate-sized file.
    lexe::util::spit(tree.payload_dir / "empty.bin",
                     std::vector<std::uint8_t>{});
    lexe::util::spit(tree.payload_dir / "sub" / "dir" / "big.txt",
                     std::string(1000, 'x'));

    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path pkg = home.path() / "app.lexe";
    lexe::PackageWriter::write(inputs, key, pkg);

    const lexe::PackageReader reader(pkg);
    CHECK(reader.has_entry("payload/empty.bin"));
    CHECK(reader.read_entry("payload/empty.bin").empty());

    const fs::path dest = home.path() / "extracted";
    reader.extract_payload(dest);

    const auto source = snapshot_tree(tree.payload_dir);
    const auto extracted = snapshot_tree(dest);
    CHECK(source == extracted);

    // Everything extracted must resolve under the destination root.
    const fs::path root = fs::weakly_canonical(dest);
    for (const auto& [rel, bytes] : extracted) {
        (void)bytes;
        const fs::path resolved = fs::weakly_canonical(dest / rel);
        const fs::path relative = resolved.lexically_relative(root);
        CHECK_FALSE(relative.empty());
        CHECK(relative.begin()->string() != "..");
    }
}

TEST_CASE("reader is movable") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    lexe::PackageReader original(pkg);
    lexe::PackageReader moved(std::move(original));
    CHECK(moved.has_entry("lexe.json"));
    moved = lexe::PackageReader(pkg);
    CHECK(moved.has_entry("metadata/hashes.json"));
}

TEST_CASE("reader rejects missing and non-zip files") {
    TempLexeHome home;
    CHECK_THROWS_AS((lexe::PackageReader{home.path() / "absent.lexe"}),
                    lexe::NotFoundError);

    const fs::path garbage = home.path() / "garbage.lexe";
    lexe::util::spit(garbage, std::string_view("this is not a zip archive"));
    CHECK_THROWS_AS((lexe::PackageReader{garbage}), lexe::VerificationError);

    const fs::path empty = home.path() / "empty.lexe";
    lexe::util::spit(empty, std::vector<std::uint8_t>{});
    CHECK_THROWS_AS((lexe::PackageReader{empty}), lexe::VerificationError);
}

// ===================================================================
// FORMAT-0.1 §2 rejection rules
// ===================================================================

TEST_CASE("reader rejects the malicious entry-path corpus") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path good = lexe::test::make_test_package(home.path(), key);
    const std::vector<RawEntry> base = read_raw_entries(good);
    const fs::path bad = home.path() / "bad.lexe";

    // Control: rebuilding the unmodified entry list stays accepted.
    write_raw_zip(bad, base);
    CHECK_NOTHROW((lexe::PackageReader{bad}));

    const std::vector<std::string> evil = {
        "../evil.txt",           // .. traversal at top level
        "payload/../../evil",    // .. traversal below payload/
        "payload/..",            // trailing .. segment
        "payload\\evil.txt",     // backslash separator
        "..\\evil.txt",          // backslash + traversal
        "C:/evil.txt",           // drive designator at start
        "c:evil.txt",            // drive-relative designator
        "payload/C:/evil.txt",   // drive designator mid-path
        "payload/./evil.txt",    // '.' segment
        "payload//evil.txt",     // empty segment
        "evil/x.txt",            // top-level dir not in allowed set
        "README.md",             // top-level file not in allowed set
        "Payload/evil.txt",      // allowed set is case-sensitive
        "lexe.json/extra",       // lexe.json must be a top-level file
    };
    for (const std::string& name : evil) {
        CAPTURE(name);
        std::vector<RawEntry> entries = base;
        entries.push_back({name, text_bytes("x")});
        write_raw_zip(bad, entries);
        CHECK_THROWS_AS((lexe::PackageReader{bad}), lexe::VerificationError);
    }

    SUBCASE("absolute path (leading slash)") {
        // miniz's writer refuses leading '/', so smuggle it in with a
        // same-length byte patch of a unique placeholder name.
        std::vector<RawEntry> entries = base;
        entries.push_back({"q9q_evil9", text_bytes("x")});
        write_raw_zip(bad, entries);
        patch_bytes(bad, "q9q_evil9", "/evil.txt");
        CHECK_THROWS_AS((lexe::PackageReader{bad}), lexe::VerificationError);
    }

    SUBCASE("NUL byte inside the name") {
        std::vector<RawEntry> entries = base;
        entries.push_back({"payload/nul#here.txt", text_bytes("x")});
        write_raw_zip(bad, entries);
        patch_bytes(bad, "payload/nul#here.txt",
                    std::string("payload/nul\0here.txt", 20));
        CHECK_THROWS_AS((lexe::PackageReader{bad}), lexe::VerificationError);
    }

    SUBCASE("symlink entry (Unix S_IFLNK external attributes)") {
        std::vector<RawEntry> entries = base;
        entries.push_back({"payload/link", text_bytes("target")});
        write_raw_zip(bad, entries);
        // (S_IFLNK | 0777) << 16
        set_entry_external_attr(bad, "payload/link", 0xA1FF0000u);
        CHECK_THROWS_AS((lexe::PackageReader{bad}), lexe::VerificationError);
    }
}

TEST_CASE("reader rejects duplicate entry paths") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path good = lexe::test::make_test_package(home.path(), key);
    std::vector<RawEntry> entries = read_raw_entries(good);

    // Duplicate an existing payload entry (identical name, same bytes).
    const auto it = std::find_if(
        entries.begin(), entries.end(),
        [](const RawEntry& e) { return e.name == "payload/data.txt"; });
    REQUIRE(it != entries.end());
    entries.push_back(*it);

    const fs::path bad = home.path() / "dup.lexe";
    write_raw_zip(bad, entries);
    CHECK_THROWS_AS((lexe::PackageReader{bad}), lexe::VerificationError);
}

TEST_CASE("reader rejects packages with a required entry missing") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path good = lexe::test::make_test_package(home.path(), key);
    const std::vector<RawEntry> base = read_raw_entries(good);
    const fs::path bad = home.path() / "missing.lexe";

    const std::vector<std::string> required = {
        "lexe.json",
        "signatures/manifest.sig",
        "signatures/payload.sig",
        "metadata/hashes.json",
    };
    for (const std::string& name : required) {
        CAPTURE(name);
        std::vector<RawEntry> entries;
        for (const RawEntry& e : base) {
            if (e.name != name) entries.push_back(e);
        }
        REQUIRE(entries.size() == base.size() - 1);
        write_raw_zip(bad, entries);
        CHECK_THROWS_AS((lexe::PackageReader{bad}), lexe::VerificationError);
    }

    SUBCASE("no payload/ entries at all (bundled mode)") {
        std::vector<RawEntry> entries;
        for (const RawEntry& e : base) {
            if (!starts_with(e.name, "payload/")) entries.push_back(e);
        }
        REQUIRE(entries.size() < base.size());
        write_raw_zip(bad, entries);
        CHECK_THROWS_AS((lexe::PackageReader{bad}), lexe::VerificationError);
    }
}

TEST_CASE("reader accepts optional scripts/, icons/ and metadata/ entries") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path good = lexe::test::make_test_package(home.path(), key);
    std::vector<RawEntry> entries = read_raw_entries(good);
    entries.push_back({"scripts/health-check", text_bytes("#!/bin/sh\n")});
    entries.push_back({"icons/512.png", text_bytes("png-ish")});
    entries.push_back({"metadata/license.txt", text_bytes("MIT")});

    const fs::path pkg = home.path() / "extras.lexe";
    write_raw_zip(pkg, entries);
    // §2 structure is fine (hash coverage of the extras is §3's business,
    // enforced by the verify module, not by PackageReader).
    const lexe::PackageReader reader(pkg);
    CHECK(reader.has_entry("scripts/health-check"));
    CHECK(reader.has_entry("icons/512.png"));
    CHECK(reader.has_entry("metadata/license.txt"));
}

// ===================================================================
// helpers sanity — tamper_entry (used heavily by the verify suite)
// ===================================================================

TEST_CASE("tamper_entry flips bytes of exactly one entry in place") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    const std::vector<std::uint8_t> before =
        lexe::PackageReader(pkg).read_entry("payload/data.txt");
    lexe::test::tamper_entry(pkg, "payload/data.txt",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE(!bytes.empty());
                                 bytes[0] ^= 0xFF;
                             });

    const lexe::PackageReader reader(pkg); // still structurally valid
    const std::vector<std::uint8_t> after =
        reader.read_entry("payload/data.txt");
    REQUIRE(after.size() == before.size());
    CHECK(after != before);
    CHECK(after[0] == (before[0] ^ 0xFF));
    // Other entries untouched, order preserved.
    CHECK(reader.has_entry("lexe.json"));
    const std::vector<RawEntry> raw = read_raw_entries(pkg);
    for (std::size_t i = 1; i < raw.size(); ++i) {
        CHECK(raw[i - 1].name < raw[i].name);
    }

    CHECK_THROWS_AS(lexe::test::tamper_entry(
                        pkg, "payload/absent.txt",
                        [](std::vector<std::uint8_t>&) {}),
                    lexe::Error);
}

} // TEST_SUITE("package")

// Malformed-package corpus (HARDENING.md §B). Each hostile package has an
// EXPECTED FAILURE CATEGORY — the verification stage it must fail at — not
// merely "some exception". Path-traversal / separator / NUL / symlink /
// duplicate / required-missing packages are a durable corpus in
// test_package.cpp; the strict-JSON (duplicate key, UTF-8, budgets) parser
// corpus is in test_json_strict.cpp / test_manifest.cpp; the resource caps are
// in test_limits.cpp. This file adds the container-level defects and the
// manifest / key / signature / hash / architecture package defects, each
// asserted at its stage.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/package/crypto.hpp"
#include "lexe/base/error.hpp"
#include "lexe/base/limits.hpp"
#include "lexe/package/package.hpp"
#include "lexe/base/util.hpp"
#include "lexe/verify/verify.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;
using nlohmann::json;

namespace {

/// Verify `pkg` and require the FIRST failing stage to be exactly `stage` — the
/// package's expected failure category.
void expect_stage(const fs::path& pkg, bool check_arch, const char* stage) {
    CAPTURE(pkg.filename().string());
    const VerificationReport report = verify_package(pkg, check_arch);
    REQUIRE_FALSE(report.ok());
    const VerificationStage* failure = report.first_failure();
    REQUIRE(failure != nullptr);
    CHECK(std::string(failure->name) == stage);
}

/// Copy `src`, mutate its raw bytes, write to `dst`.
fs::path corrupt(const fs::path& src, const fs::path& dst,
                 const std::function<void(std::vector<std::uint8_t>&)>& mutate) {
    std::vector<std::uint8_t> bytes = util::slurp(src);
    mutate(bytes);
    util::spit(dst, bytes);
    return dst;
}

/// A structurally valid base manifest; callers mutate one field to a §5
/// violation. publicKey is `key_str` (so key-stage cases can supply a bad one).
json base_manifest(const std::string& key_str) {
    return json{
        {"lexeVersion", "0.1"},
        {"id", "com.example.app"},
        {"name", "App"},
        {"version", "1.0.0"},
        {"publisher", {{"name", "P"}, {"publicKey", key_str}}},
        {"applicationType", "native"},
        {"architectures", json::array({"x86_64", "aarch64"})},
        {"entrypoint", {{"executable", test::TestAppSpec{}.entrypoint}}},
        {"install", {{"scope", "user"}, {"mode", "bundled"}}},
    };
}

/// Pack a package whose lexe.json is exactly `manifest` (well-formed JSON, but
/// possibly §5-invalid), signed with `key`. `architectures` selects which ELF
/// the payload's entrypoint is built for — it must agree with the manifest, or
/// the payload-role stage fires before the stage under test.
fs::path pack_manifest(const fs::path& work, const crypto::KeyPair& key,
                       const json& manifest, const std::string& tag,
                       const std::vector<std::string>& architectures = {
                           "x86_64", "aarch64"}) {
    test::TestAppSpec spec;
    spec.public_key = test::encode_public_key_str(key.public_key);
    spec.architectures = architectures;
    const test::TestAppTree tree =
        test::make_test_app_tree(work / ("tree-" + tag), spec);
    util::spit(tree.manifest_file, std::string_view(manifest.dump(2) + "\n"));
    PackageWriter::Inputs in;
    in.payload_dir = tree.payload_dir;
    in.manifest_file = tree.manifest_file;
    const fs::path out = work / (tag + ".lexe");
    PackageWriter::write(in, key, out);
    return out;
}

} // namespace

TEST_SUITE("hostile_packages") {

TEST_CASE("container-level defects fail at the structure stage") {
    test::TempLexeHome home;
    const fs::path w = home.path();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path good = test::make_test_package(w, key);
    REQUIRE(verify_package(good, false).ok()); // control

    // empty file
    util::spit(w / "empty.lexe", std::vector<std::uint8_t>{});
    expect_stage(w / "empty.lexe", false, "structure");

    // pure garbage
    util::spit(w / "garbage.lexe", std::string_view("not a zip at all!!!!"));
    expect_stage(w / "garbage.lexe", false, "structure");

    // truncated archive (first half only)
    expect_stage(corrupt(good, w / "trunc.lexe",
                         [](auto& b) { b.resize(b.size() / 2); }),
                 false, "structure");

    // invalid magic: clobber the End-Of-Central-Directory signature (the last
    // 22 bytes, no comment) so miniz cannot open the archive at all.
    expect_stage(corrupt(good, w / "magic.lexe",
                         [](auto& b) {
                             if (b.size() >= 22) {
                                 for (int i = 0; i < 4; ++i) b[b.size() - 22 + i] = 0;
                             }
                         }),
                 false, "structure");

    // trailing data appended after the archive
    expect_stage(corrupt(good, w / "trailing.lexe",
                         [](auto& b) {
                             for (int i = 0; i < 64; ++i) b.push_back(0x5a);
                         }),
                 false, "structure");
}

TEST_CASE("a decompression bomb is refused by VERIFY, not only by install") {
    // REGRESSION, and the interesting part is which command used to accept it.
    //
    // The aggregate resource guards -- total uncompressed size, and the
    // expansion ratio past a grace threshold -- lived only in
    // `extract_payload()`. So `lexe install` refused a bomb and `lexe verify`
    // reported OK on the SAME FILE, with all seven stages green. Reproduced
    // before the fix: a 413 KB package carrying one 400 MiB entry of zeroes,
    // correct hashes and real signatures, 1015x expansion, `verify` exit 0 and
    // `install` exit 3.
    //
    // That gap matters more than the bomb does. The guard did fire before
    // extraction, so nothing was ever unpacked -- but `verify` is the command a
    // CI job, a repository gate or a cautious user runs to decide whether a
    // package is ACCEPTABLE, and a gate that passes what the installer will
    // refuse hands out an assurance the runtime does not honour.
    //
    // Found by the independent conformance validator in tools/lexe-conformance,
    // which disagreed with `lexe verify` and turned out to be right. It is the
    // reason that validator does not share this implementation's parser.
    //
    // The guard now lives in the PackageReader constructor, so it applies to
    // every consumer at once -- verify, install, info, inspect -- and is read
    // from the central directory's declared sizes, which means a bomb is
    // refused before a single byte of it is decompressed.
    test::TempLexeHome home;
    const fs::path w = home.path();
    const crypto::KeyPair key = test::make_keypair();

    const fs::path good = test::make_test_package(w, key);
    REQUIRE(verify_package(good, false).ok()); // control

    // Past the 16 MiB grace threshold, and vastly past the 200x ratio: 32 MiB
    // of zeroes deflates to a few kilobytes. Zeroes rather than a pattern
    // because the point is the RATIO, and this keeps the test quick.
    test::TestAppSpec spec;
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree =
        test::make_test_app_tree(w / "tree-bomb", spec);
    const std::vector<std::uint8_t> zeroes(
        static_cast<std::size_t>(limits::kRatioGraceBytes) * 2, 0);
    util::spit(tree.payload_dir / "big.dat", zeroes);

    PackageWriter::Inputs in;
    in.payload_dir = tree.payload_dir;
    in.manifest_file = tree.manifest_file;
    const fs::path bomb = w / "bomb.lexe";
    PackageWriter::write(in, key, bomb);

    // Signed, hashed and structurally perfect -- and still refused, at the
    // FIRST stage, which is the only stage that can refuse it without reading
    // the bytes it is refusing.
    expect_stage(bomb, false, "structure");

    // And the reason must name the guard, because "structure" alone would send
    // someone looking for a corrupt archive.
    const VerificationReport report = verify_package(bomb, false);
    const VerificationStage* failure = report.first_failure();
    REQUIRE(failure != nullptr);
    INFO("detail was: " << failure->detail);
    CHECK(failure->detail.find("decompression-bomb guard") != std::string::npos);

    // Opening it directly must refuse too: the gate is the reader, not the
    // verifier, so nothing can reach the entries by going around verify().
    CHECK_THROWS_AS(PackageReader{bomb}, lexe::Error);
}

TEST_CASE("manifest §5 violations fail at the manifest stage") {
    test::TempLexeHome home;
    const fs::path w = home.path();
    const crypto::KeyPair key = test::make_keypair();
    const std::string good_key = test::encode_public_key_str(key.public_key);

    auto pack = [&](const std::function<void(json&)>& mutate,
                    const std::string& tag) {
        json m = base_manifest(good_key);
        mutate(m);
        return pack_manifest(w, key, m, tag);
    };

    expect_stage(pack([](json& m) { m["name"] = ""; }, "empty-name"), false,
                 "manifest");
    expect_stage(pack([](json& m) { m["id"] = "nodot"; }, "bad-id"), false,
                 "manifest");
    expect_stage(pack([](json& m) { m["version"] = std::string(300, 'x'); },
                      "long-version"),
                 false, "manifest");
    expect_stage(pack([](json& m) { m.erase("entrypoint"); }, "no-entrypoint"),
                 false, "manifest");
    expect_stage(pack([](json& m) { m["entrypoint"]["executable"] =
                                        "../escape"; },
                      "entrypoint-escape"),
                 false, "manifest");
    expect_stage(pack([](json& m) { m["architectures"] =
                                        json::array({"sparc"}); },
                      "bad-arch"),
                 false, "manifest");
    expect_stage(pack([](json& m) { m["install"]["mode"] = "network"; },
                      "network-mode"),
                 false, "manifest");
    expect_stage(pack([](json& m) { m["applicationType"] = "wine"; },
                      "bad-type"),
                 false, "manifest");
}

TEST_CASE("verify refuses a permission install would refuse") {
    // REGRESSION, and the same defect shape as the decompression bomb: `verify`
    // said yes to a package `install` said no to.
    //
    // `Manifest::parse` checks only that `permissions` is an array of strings.
    // The closed 0.1 vocabulary and the no-duplicates rule were enforced by
    // `normalize_permissions`, which every CONSUMER runs -- but which the
    // verification pipeline did not. `verify` is the command a CI job or a
    // repository gate runs to decide whether a package is acceptable, so the
    // gap meant a publisher could ship something that verified perfectly and
    // failed for every user at install.
    test::TempLexeHome home;
    const fs::path w = home.path();
    const crypto::KeyPair key = test::make_keypair();

    json base = base_manifest(test::encode_public_key_str(key.public_key));
    REQUIRE(verify_package(pack_manifest(w, key, base, "perm-ok"), false).ok());

    // Outside the frozen vocabulary.
    json unknown = base;
    unknown["permissions"] = json::array({"camera"});
    expect_stage(pack_manifest(w, key, unknown, "perm-unknown"), false,
                 "manifest");

    // In the vocabulary, but repeated: a duplicate changes the permission
    // DIGEST that install records, so it is not merely cosmetic.
    json duplicated = base;
    duplicated["permissions"] = json::array({"network", "network"});
    expect_stage(pack_manifest(w, key, duplicated, "perm-dup"), false,
                 "manifest");

    // Both legal ids together must still pass, or the fix would have broken
    // every package that asks for anything.
    json legal = base;
    legal["permissions"] = json::array({"network", "user-files-selected"});
    CHECK(verify_package(pack_manifest(w, key, legal, "perm-legal"), false).ok());
}

TEST_CASE("a publisher key must have exactly one spelling") {
    // REGRESSION. Base64 leaves the unused bits of the final group free, so a
    // 32-byte key has many valid spellings that all decode identically. The key
    // string is an IDENTITY -- `installer.cpp` pins the trusted publisher by
    // comparing the manifest string against the recorded one -- so a key with
    // more than one name means the update-trust anchor turns on a string that
    // was never required to be unique: a re-spelling of the very same key reads
    // as a changed key.
    //
    // `trust.cpp` already required canonical encoding of trust records; the
    // manifest was the odd one out. The check now lives in decode_public_key, so
    // every consumer inherits it.
    test::TempLexeHome home;
    const fs::path w = home.path();
    const crypto::KeyPair key = test::make_keypair();
    const std::string canonical = test::encode_public_key_str(key.public_key);

    // Find a different spelling that decodes to the SAME bytes, by varying the
    // final significant character across the alphabet. Derived rather than
    // hard-coded so the case does not depend on which key was generated.
    static constexpr std::string_view kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const std::size_t last = canonical.find_last_not_of('=');
    REQUIRE(last != std::string::npos);
    const std::string prefix = "ed25519:";
    const std::vector<std::uint8_t> want =
        util::base64_decode(std::string_view(canonical).substr(prefix.size()));

    std::string non_canonical;
    for (const char c : kAlphabet) {
        if (c == canonical[last]) continue;
        std::string candidate = canonical;
        candidate[last] = c;
        try {
            if (util::base64_decode(
                    std::string_view(candidate).substr(prefix.size())) == want) {
                non_canonical = candidate;
                break;
            }
        } catch (const std::exception&) {
            // Not a decodable variant; try the next.
        }
    }
    REQUIRE_FALSE(non_canonical.empty());
    REQUIRE(non_canonical != canonical);
    INFO("canonical:     " << canonical);
    INFO("non-canonical: " << non_canonical);

    // The premise: it really is the same key, so nothing downstream could tell
    // these two packages apart by their key BYTES.
    CHECK(util::base64_decode(
              std::string_view(non_canonical).substr(prefix.size())) == want);

    json manifest = base_manifest(non_canonical);
    // Signed with the real key, so only the SPELLING is wrong -- the signature
    // over the manifest is genuine and stage 4 would have passed.
    expect_stage(pack_manifest(w, key, manifest, "noncanon-key"), false, "key");

    // The canonical spelling of the same key must still verify.
    CHECK(verify_package(
              pack_manifest(w, key, base_manifest(canonical), "canon-key"),
              false)
              .ok());
}

TEST_CASE("undecodable publisher keys fail at the key stage") {
    test::TempLexeHome home;
    const fs::path w = home.path();
    const crypto::KeyPair key = test::make_keypair();

    json bad_prefix = base_manifest("not-ed25519:AAAA");
    expect_stage(pack_manifest(w, key, bad_prefix, "bad-prefix"), false, "key");

    json bad_b64 = base_manifest("ed25519:@@@@not-base64@@@@");
    expect_stage(pack_manifest(w, key, bad_b64, "bad-b64"), false, "key");

    // Decodes, but to 31 bytes instead of 32.
    json short_key = base_manifest(
        "ed25519:" + util::base64_encode(std::vector<std::uint8_t>(31, 0).data(),
                                         31));
    expect_stage(pack_manifest(w, key, short_key, "short-key"), false, "key");
}

TEST_CASE("signature defects fail at the signature stages") {
    test::TempLexeHome home;
    const fs::path w = home.path();
    const crypto::KeyPair key = test::make_keypair();

    // Zeroed manifest signature.
    fs::path p1 = test::make_test_package(w, key, {});
    test::tamper_entry(p1, "signatures/manifest.sig",
                       [](std::vector<std::uint8_t>& b) {
                           std::fill(b.begin(), b.end(), std::uint8_t{0});
                       });
    expect_stage(p1, false, "manifest-signature");

    // Truncated manifest signature (< 64 bytes).
    fs::path p2 = test::make_test_package(w, key, []{ test::TestAppSpec s; s.version="1.0.1"; return s; }());
    test::tamper_entry(p2, "signatures/manifest.sig",
                       [](std::vector<std::uint8_t>& b) { b.resize(10); });
    expect_stage(p2, false, "manifest-signature");

    // Zeroed payload signature (manifest sig still valid → fails at stage 5).
    fs::path p3 = test::make_test_package(w, key, []{ test::TestAppSpec s; s.version="1.0.2"; return s; }());
    test::tamper_entry(p3, "signatures/payload.sig",
                       [](std::vector<std::uint8_t>& b) {
                           std::fill(b.begin(), b.end(), std::uint8_t{0});
                       });
    expect_stage(p3, false, "payload-signature");
}

TEST_CASE("a tampered payload file fails at the hashes stage") {
    test::TempLexeHome home;
    const fs::path w = home.path();
    const crypto::KeyPair key = test::make_keypair();
    fs::path pkg = test::make_test_package(w, key, {});
    test::tamper_entry(pkg, "payload/data.txt",
                       [](std::vector<std::uint8_t>& b) {
                           b.push_back('!'); // change the covered bytes
                       });
    expect_stage(pkg, false, "hashes");
}

TEST_CASE("an architecture-incompatible package fails at the compatibility stage") {
    test::TempLexeHome home;
    const fs::path w = home.path();
    const crypto::KeyPair key = test::make_keypair();
    // List only the architecture that is NOT the host.
    const std::string other =
        host_architecture() == "x86_64" ? "aarch64" : "x86_64";
    json m = base_manifest(test::encode_public_key_str(key.public_key));
    m["architectures"] = json::array({other});
    const fs::path pkg = pack_manifest(w, key, m, "wrong-arch", {other});
    // Passes structure/manifest/key/signatures/hashes, fails compatibility.
    expect_stage(pkg, /*check_arch=*/true, "compatibility");
}

} // TEST_SUITE("hostile_packages")

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

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/package.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"

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
        {"entrypoint", {{"executable", "bin/hello.sh"}}},
        {"install", {{"scope", "user"}, {"mode", "bundled"}}},
    };
}

/// Pack a package whose lexe.json is exactly `manifest` (well-formed JSON, but
/// possibly §5-invalid), signed with `key`.
fs::path pack_manifest(const fs::path& work, const crypto::KeyPair& key,
                       const json& manifest, const std::string& tag) {
    test::TestAppSpec spec;
    spec.public_key = test::encode_public_key_str(key.public_key);
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
    const fs::path pkg = pack_manifest(w, key, m, "wrong-arch");
    // Passes structure/manifest/key/signatures/hashes, fails compatibility.
    expect_stage(pkg, /*check_arch=*/true, "compatibility");
}

} // TEST_SUITE("hostile_packages")

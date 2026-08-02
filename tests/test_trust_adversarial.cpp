// Adversarial trust tests (runtime-trust WS3/WS4). Each case is a concrete
// attempt to bypass local trust continuity; every one must be refused with a
// typed error and leave prior state intact.

#include <doctest/doctest.h>

#include "helpers.hpp"
#include "lock_fake.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/lock.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/trust.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

constexpr const char* kId = "com.example.hello";

struct TempWork {
    fs::path dir;
    TempWork() : dir(test::unique_temp_dir("lexe-trust-adv-")) {
        fs::create_directories(dir);
    }
    ~TempWork() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

std::string enc(const crypto::KeyPair& k) {
    return crypto::encode_public_key(k.public_key);
}

fs::path pkg(const fs::path& work, const crypto::KeyPair& key,
             const std::string& version) {
    test::TestAppSpec spec;
    spec.id = kId;
    spec.version = version;
    return test::make_test_package(work, key, spec);
}

/// A package for kId whose manifest requests `perms`.
fs::path pkg_perms(const fs::path& work, const crypto::KeyPair& key,
                   const std::string& version,
                   const std::vector<std::string>& perms) {
    test::TestAppSpec spec;
    spec.id = kId;
    spec.version = version;
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree =
        test::make_test_app_tree(work / ("t-" + version), spec);
    nlohmann::json m = nlohmann::json::parse(util::slurp_text(tree.manifest_file));
    m["permissions"] = perms;
    util::spit(tree.manifest_file, std::string_view(m.dump(2) + "\n"));
    PackageWriter::Inputs in;
    in.payload_dir = tree.payload_dir;
    in.manifest_file = tree.manifest_file;
    const fs::path out = work / (version + "-perms.lexe");
    PackageWriter::write(in, key, out);
    return out;
}

} // namespace

TEST_SUITE("trust-adversarial") {

TEST_CASE("a mixed-case / non-canonical key encoding in a record is rejected") {
    const crypto::KeyPair key = test::make_keypair();
    TrustRecord r;
    r.schema_version = 1;
    r.app_id = kId;
    r.public_key = enc(key);
    r.fingerprint = key_fingerprint(key.public_key).full;
    r.first_seen = r.last_seen = "t";
    // Corrupt the base64 to a non-canonical (lowercased) form.
    std::string mangled = r.public_key;
    for (char& c : mangled) {
        if (c >= 'A' && c <= 'Z') { c = static_cast<char>(c - 'A' + 'a'); break; }
    }
    r.public_key = mangled;
    CHECK_THROWS_AS(TrustRecord::from_json(r.to_json()), CorruptTrustError);
}

#ifndef _WIN32
TEST_CASE("a trust record that is a symlink is refused (path substitution)") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();

    // Point <id>.json at an attacker-controlled file via a symlink.
    const fs::path elsewhere = home.path() / "evil.json";
    TrustRecord r;
    r.schema_version = 1;
    r.app_id = kId;
    r.public_key = enc(key);
    r.fingerprint = key_fingerprint(key.public_key).full;
    r.first_seen = r.last_seen = "t";
    util::spit(elsewhere, std::string_view(r.to_json()));

    const fs::path record = registry.trust_record_file(kId);
    fs::create_directories(record.parent_path());
    std::error_code ec;
    fs::create_symlink(elsewhere, record, ec);
    REQUIRE_FALSE(ec);
    CHECK_THROWS_AS(TrustStore(paths).read(kId), CorruptTrustError);
}
#endif

TEST_CASE("a blocked application cannot be un-blocked by a package update") {
    test::TempLexeHome home;
    TempWork work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();

    Installer(paths).install(pkg(work.dir, key, "1.0.0"));
    TrustStore(paths).block(kId);
    // A perfectly valid, same-key, newer package must NOT clear the block.
    CHECK_THROWS_AS(Installer(paths).install(pkg(work.dir, key, "2.0.0")),
                    BlockedKeyError);
    CHECK(TrustStore(paths).read(kId).value().blocked);
    CHECK(Registry(paths).current_version(kId) == "1.0.0");
}

TEST_CASE("a changed key is refused regardless of a higher version") {
    test::TempLexeHome home;
    TempWork work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair a = test::make_keypair();
    const crypto::KeyPair b = test::make_keypair();

    Installer(paths).install(pkg(work.dir, a, "1.0.0"));
    // A DIFFERENT key at a much higher version is still a changed-key rejection.
    CHECK_THROWS_AS(Installer(paths).install(pkg(work.dir, b, "9.9.9")),
                    ChangedKeyError);
    CHECK(Registry(paths).read_record(kId).publisher_key == enc(a));
}

TEST_CASE("a changed key is refused even when it REDUCES permissions") {
    test::TempLexeHome home;
    TempWork work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair a = test::make_keypair();
    const crypto::KeyPair b = test::make_keypair();

    Installer(paths).install(pkg_perms(work.dir, a, "1.0.0", {"network"}));
    // Key B asks for FEWER permissions and a higher version — a changed key is
    // rejected before any permission logic; reducing scope is not a free pass.
    CHECK_THROWS_AS(
        Installer(paths).install(pkg_perms(work.dir, b, "2.0.0", {})),
        ChangedKeyError);
}

TEST_CASE("an identical publisher NAME with a different key does not inherit trust") {
    test::TempLexeHome home;
    TempWork work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair a = test::make_keypair();
    const crypto::KeyPair b = test::make_keypair();

    // Both packages carry the same publisher display name ("Test Publisher");
    // only the KEY differs. The display string is not identity.
    Installer(paths).install(pkg(work.dir, a, "1.0.0"));
    CHECK_THROWS_AS(Installer(paths).install(pkg(work.dir, b, "2.0.0")),
                    ChangedKeyError);
}

TEST_CASE("a corrupt trust record during recovery is left closed, not overwritten") {
    test::TempLexeHome home;
    TempWork work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path package = pkg(work.dir, key, "1.0.0");

    {
        util::set_env("LEXE_TEST_FAULT", "after-promote");
        CHECK_THROWS(Installer(paths).install(package));
        util::unset_env("LEXE_TEST_FAULT");
    }
    // A corrupt trust record appears before recovery runs.
    util::spit(Registry(paths).trust_record_file(kId),
               std::string_view("{ corrupt trust"));

    // Recovery completes the committed install and must NOT throw or silently
    // overwrite the corrupt record (best-effort trust persistence).
    CHECK_NOTHROW(Installer(paths).recover_all());
    CHECK(Registry(paths).is_installed(kId));
    CHECK_THROWS_AS(TrustStore(paths).read(kId), CorruptTrustError); // still closed
}

TEST_CASE("a trust mutation in progress serializes with a same-id install") {
    test::TempLexeHome home;
    TempWork work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();

    auto locks = std::make_shared<test::FakeLockManager>();
    // Something is mutating this app's trust (holds the per-app mutation lock).
    AppLock trust_op = locks->lock_app_mutation(kId, "trust", WaitPolicy::none());

    Installer installer(paths, locks);
    installer.set_mutation_wait(WaitPolicy::none());
    CHECK_THROWS_AS(installer.install(pkg(work.dir, key, "1.0.0")), BusyError);
}

} // TEST_SUITE("trust-adversarial")

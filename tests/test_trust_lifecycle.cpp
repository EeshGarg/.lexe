// Trust persistence + transaction/recovery integration (runtime-trust WS4).
// Proves trust is recorded ONLY after a committed install, never for a failed
// one, and that crash recovery completes trust persistence for a promoted
// transaction (and never fabricates it for a rolled-back one), idempotently.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/trust.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

constexpr const char* kId = "com.example.hello";

struct ScopedFault {
    explicit ScopedFault(const std::string& site) {
        util::set_env("LEXE_TEST_FAULT", site);
    }
    ~ScopedFault() { util::unset_env("LEXE_TEST_FAULT"); }
};

fs::path build_pkg(const fs::path& work, const crypto::KeyPair& key,
                   const std::string& version) {
    test::TestAppSpec spec;
    spec.id = kId;
    spec.version = version;
    return test::make_test_package(work, key, spec);
}

std::string enc(const crypto::KeyPair& k) {
    return crypto::encode_public_key(k.public_key);
}

} // namespace

TEST_SUITE("trust-lifecycle") {

TEST_CASE("install persists the trust binding only after a committed install") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();
    const TrustStore store(paths);

    CHECK_FALSE(store.exists(kId));
    Installer(paths).install(build_pkg(work, key, "1.0.0"));

    REQUIRE(store.exists(kId));
    const TrustRecord r = store.read(kId).value();
    CHECK(r.app_id == kId);
    CHECK(r.public_key == enc(key));
    CHECK(r.fingerprint == key_fingerprint(key.public_key).full);
    CHECK_FALSE(r.explicitly_trusted); // a plain install only ACCEPTS the key
    CHECK(!r.first_seen.empty());
}

TEST_CASE("install --trust records an explicit local trust decision") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();

    InstallOptions opts;
    opts.explicit_trust = true;
    Installer(paths).install(build_pkg(work, key, "1.0.0"), opts);

    const TrustRecord r = TrustStore(paths).read(kId).value();
    CHECK(r.explicitly_trusted);
    CHECK(r.trust_provenance == "install-trust");
}

TEST_CASE("a same-key update keeps the first-seen time and the binding") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();

    Installer(paths).install(build_pkg(work, key, "1.0.0"));
    const TrustRecord r1 = TrustStore(paths).read(kId).value();
    Installer(paths).install(build_pkg(work, key, "2.0.0")); // same key update
    const TrustRecord r2 = TrustStore(paths).read(kId).value();

    CHECK(r2.public_key == r1.public_key);
    CHECK(r2.first_seen == r1.first_seen); // continuity preserved
}

TEST_CASE("a failed (pre-promotion) install persists NO trust") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = build_pkg(work, key, "1.0.0");

    {
        ScopedFault fault("before-promote");
        CHECK_THROWS(Installer(paths).install(pkg));
    }
    CHECK_FALSE(TrustStore(paths).exists(kId)); // never committed → no trust

    // Recovery rolls the pre-promotion transaction back and must NOT fabricate
    // a trust record for an install that never happened.
    Installer(paths).recover_all();
    CHECK_FALSE(TrustStore(paths).exists(kId));
    CHECK_FALSE(Registry(paths).is_installed(kId));
}

TEST_CASE("recovery completes trust persistence for a committed install, idempotently") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = build_pkg(work, key, "1.0.0");

    {
        // Crash AFTER promotion: the version is committed but the post-commit
        // trust write never ran.
        ScopedFault fault("after-promote");
        CHECK_THROWS(Installer(paths).install(pkg));
    }
    CHECK_FALSE(TrustStore(paths).exists(kId)); // trust not yet written

    Installer(paths).recover_all(); // completes forward + persists the binding
    REQUIRE(TrustStore(paths).exists(kId));
    CHECK(TrustStore(paths).read(kId).value().public_key == enc(key));

    Installer(paths).recover_all(); // idempotent
    CHECK(TrustStore(paths).read(kId).value().public_key == enc(key));
}

} // TEST_SUITE("trust-lifecycle")

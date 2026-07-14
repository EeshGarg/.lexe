// updater module tests — FORMAT-0.1 §7 end-to-end over file:// URLs
// (ARCHITECTURE.md #Tests: old→new, wrong key, wrong hash, downgrade,
// wrong id; plus missing channel, equal-version no-op, tampered update.json
// signature, previous-version retention and rollback, set_source).
//
// The "server" is a directory inside the temp LEXE_HOME that hosts
// update.json, update.json.sig and the packaged versions; every URL the
// updater sees is file://. Every test case constructs UpdaterFixture, whose
// first member is TempLexeHome, so LEXE_HOME always points into a fresh
// temp directory.
//
// The installer module is developed in parallel, so the baseline "installed
// application" is laid out with Registry + PackageReader primitives directly
// (the exact FORMAT-0.1 §9 shapes the installer produces); rollback is
// likewise exercised at the registry level.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/updater.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// file:// URL for a local path (forward slashes, minimal percent-encoding).
/// "C:/x y" -> "file:///C:/x%20y"; "/tmp/x" -> "file:///tmp/x".
std::string to_file_url(const fs::path& p) {
    const std::string generic = p.generic_string();
    std::string encoded;
    encoded.reserve(generic.size() + 8);
    for (const char c : generic) {
        const bool keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                          c == '_' || c == '~' || c == '/' || c == ':';
        if (keep) {
            encoded.push_back(c);
        } else {
            static const char* hex = "0123456789ABCDEF";
            encoded.push_back('%');
            encoded.push_back(hex[(static_cast<unsigned char>(c) >> 4) & 0xF]);
            encoded.push_back(hex[static_cast<unsigned char>(c) & 0xF]);
        }
    }
    if (!encoded.empty() && encoded.front() == '/') {
        return "file://" + encoded; // POSIX absolute path
    }
    return "file:///" + encoded; // Windows drive path
}

/// Distinguishable payload marker for a given package version.
std::string payload_marker(const std::string& id, const std::string& version) {
    return "payload of " + id + " version " + version + "\n";
}

/// Shared per-test environment: fresh LEXE_HOME, a publisher keypair, a
/// file:// "server" directory, and helpers to install a baseline version and
/// publish signed update manifests + packages.
struct UpdaterFixture {
    lexe::test::TempLexeHome home; // MUST be first: sets LEXE_HOME
    lexe::Paths paths = lexe::Paths::detect();
    lexe::Registry registry{paths};
    lexe::Updater updater{paths};
    lexe::crypto::KeyPair key = lexe::test::make_keypair();
    std::string id = "com.example.hello";
    fs::path server = home.path() / "server";
    fs::path work = home.path() / "work";
    std::string update_url = to_file_url(server / "update.json");
    int package_counter = 0;

    UpdaterFixture() { fs::create_directories(server); }

    /// Build a signed .lexe for `version` whose payload data.txt carries a
    /// version marker (old and new payloads must be distinguishable). The
    /// package manifest's updates block points at `update_url`.
    fs::path build_package(const std::string& version,
                           const lexe::crypto::KeyPair& pkg_key,
                           const std::string& pkg_id = "",
                           const fs::path& out_dir = {}) {
        ++package_counter;
        lexe::test::TestAppSpec spec;
        spec.id = pkg_id.empty() ? id : pkg_id;
        spec.version = version;
        spec.update_url = update_url;
        spec.public_key = lexe::test::encode_public_key_str(pkg_key.public_key);
        const std::string tag =
            spec.id + "-" + version + "-" + std::to_string(package_counter);
        const lexe::test::TestAppTree tree =
            lexe::test::make_test_app_tree(work / ("tree-" + tag), spec);
        lexe::util::spit(tree.payload_dir / "data.txt",
                         std::string_view(payload_marker(spec.id, version)));
        lexe::PackageWriter::Inputs inputs;
        inputs.payload_dir = tree.payload_dir;
        inputs.manifest_file = tree.manifest_file;
        const fs::path out =
            (out_dir.empty() ? work : out_dir) / (tag + ".lexe");
        lexe::PackageWriter::write(inputs, pkg_key, out);
        return out;
    }

    /// Lay out an installed app per FORMAT-0.1 §9 (what the installer module
    /// produces): versions/<v>/ payload, manifest.json, installation.json
    /// with the pinned publisher key + update source, and `current`.
    fs::path install_baseline(const std::string& version) {
        const fs::path pkg = build_package(version, key);
        const lexe::PackageReader reader(pkg);
        reader.extract_payload(registry.version_dir(id, version));
        registry.write_manifest_bytes(id, reader.read_entry("lexe.json"));

        lexe::InstallationRecord record;
        record.id = id;
        record.version = version;
        record.source = pkg.string();
        record.publisher_key =
            lexe::test::encode_public_key_str(key.public_key);
        record.channel = "stable";
        record.update_url = update_url;
        record.installed_at = lexe::util::now_utc_string();
        registry.write_record(record);
        registry.set_current_version(id, version);
        return pkg;
    }

    /// Serve `text` as update.json plus its detached signature (raw 64-byte
    /// Ed25519 over the exact bytes, FORMAT-0.1 §7) signed with `sig_key`.
    void serve_update_json(const std::string& text,
                           const lexe::crypto::KeyPair& sig_key,
                           const fs::path& dir = {}) {
        const fs::path dest = dir.empty() ? server : dir;
        lexe::util::spit(dest / "update.json", std::string_view(text));
        const std::vector<std::uint8_t> bytes(text.begin(), text.end());
        const lexe::crypto::Signature sig = lexe::crypto::sign(bytes, sig_key);
        lexe::util::spit(dest / "update.json.sig", sig.data(), sig.size());
    }

    /// Well-formed update.json text advertising `version` at `package_path`
    /// (sha256 computed from the file unless overridden).
    std::string update_json_text(const std::string& version,
                                 const fs::path& package_path,
                                 const std::string& channel = "stable",
                                 const std::string& manifest_id = "",
                                 const std::string& sha_override = "") {
        nlohmann::json pkg;
        pkg["url"] = to_file_url(package_path);
        pkg["sha256"] = sha_override.empty()
                            ? lexe::crypto::sha256_file_hex(package_path)
                            : sha_override;
        nlohmann::json entry;
        entry["version"] = version;
        entry["package"] = pkg;
        entry["minimumRuntime"] = "0.1";
        nlohmann::json j;
        j["lexeVersion"] = "0.1";
        j["id"] = manifest_id.empty() ? id : manifest_id;
        j["channels"][channel] = entry;
        return j.dump(2) + "\n";
    }

    /// Publish a fully consistent update: package on the server + signed
    /// update.json describing it. Returns the package path.
    fs::path publish_update(const std::string& version,
                            const lexe::crypto::KeyPair& pkg_key) {
        const fs::path pkg = build_package(version, pkg_key, "", server);
        serve_update_json(update_json_text(version, pkg), key);
        return pkg;
    }
};

} // namespace

TEST_SUITE("updater") {

TEST_CASE("check reports an available update without side effects") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");
    const fs::path new_pkg = fx.publish_update("2.0.0", fx.key);

    const lexe::UpdateCheck chk = fx.updater.check(fx.id);
    CHECK(chk.id == fx.id);
    CHECK(chk.installed_version == "1.0.0");
    CHECK(chk.available_version == "2.0.0");
    CHECK(chk.update_available);
    CHECK(chk.package_url == to_file_url(new_pkg));
    CHECK(chk.package_sha256 == lexe::crypto::sha256_file_hex(new_pkg));

    // Dry run: nothing downloaded, nothing extracted, nothing flipped.
    CHECK(fx.registry.current_version(fx.id) == "1.0.0");
    CHECK_FALSE(fs::exists(fx.registry.version_dir(fx.id, "2.0.0")));
    CHECK_FALSE(fs::exists(fx.paths.cache_dir() / "updates"));
    CHECK(fx.registry.read_record(fx.id).version == "1.0.0");
    CHECK(fx.registry.read_manifest(fx.id).version == "1.0.0");
}

TEST_CASE("apply performs the happy-path old->new update") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");
    const fs::path new_pkg = fx.publish_update("2.0.0", fx.key);

    const lexe::InstallResult result = fx.updater.apply(fx.id);
    CHECK(result.id == fx.id);
    CHECK(result.version == "2.0.0");
    CHECK(result.app_dir == fx.registry.app_dir(fx.id));

    // current flipped to the new version and its payload was extracted.
    CHECK(fx.registry.current_version(fx.id) == "2.0.0");
    CHECK(lexe::util::slurp_text(fx.registry.version_dir(fx.id, "2.0.0") /
                                 "data.txt") == payload_marker(fx.id, "2.0.0"));

    // Previous version directory retained, contents intact (§7 rollback).
    CHECK(fs::exists(fx.registry.version_dir(fx.id, "1.0.0")));
    CHECK(lexe::util::slurp_text(fx.registry.version_dir(fx.id, "1.0.0") /
                                 "data.txt") == payload_marker(fx.id, "1.0.0"));
    CHECK(fs::exists(fx.registry.version_dir(fx.id, "1.0.0") / "bin"));

    // Records updated; trust anchor and user-approved source unchanged.
    const lexe::InstallationRecord record = fx.registry.read_record(fx.id);
    CHECK(record.version == "2.0.0");
    CHECK(record.source == to_file_url(new_pkg));
    CHECK(record.publisher_key ==
          lexe::test::encode_public_key_str(fx.key.public_key));
    CHECK(record.update_url == fx.update_url);
    CHECK(record.channel == "stable");
    CHECK(fx.registry.read_manifest(fx.id).version == "2.0.0");

    // The package was downloaded into the cache (§7 "download to cache").
    CHECK(fs::exists(fx.paths.cache_dir() / "updates" / fx.id /
                     "package.lexe"));
}

TEST_CASE("previous version is retained and rollback works after update") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");
    fx.publish_update("2.0.0", fx.key);
    fx.updater.apply(fx.id);
    REQUIRE(fx.registry.current_version(fx.id) == "2.0.0");

    // Roll back at the registry level (Installer::rollback is the installer
    // module's surface; the §9 primitives it flips are exercised here).
    fx.registry.set_current_version(fx.id, "1.0.0");
    lexe::InstallationRecord record = fx.registry.read_record(fx.id);
    record.version = "1.0.0";
    fx.registry.write_record(record);

    CHECK(fx.registry.current_version(fx.id) == "1.0.0");
    CHECK(lexe::util::slurp_text(fx.registry.version_dir(fx.id, "1.0.0") /
                                 "data.txt") == payload_marker(fx.id, "1.0.0"));

    // After the rollback the same update is offered again and can be
    // re-applied into the still-existing versions/2.0.0 directory.
    const lexe::UpdateCheck chk = fx.updater.check(fx.id);
    CHECK(chk.installed_version == "1.0.0");
    CHECK(chk.update_available);
    const lexe::InstallResult again = fx.updater.apply(fx.id);
    CHECK(again.version == "2.0.0");
    CHECK(fx.registry.current_version(fx.id) == "2.0.0");
    CHECK(lexe::util::slurp_text(fx.registry.version_dir(fx.id, "2.0.0") /
                                 "data.txt") == payload_marker(fx.id, "2.0.0"));
}

// Regression: apply() must commit the new version through the SAME canonical
// path as install (HARDENING.md §A) — the per-version meta store, the active
// hashes.json and the entrypoint exec bit. Before the fix, apply() hand-rolled
// a partial commit, so `lexe repair` compared the new payload against the
// PRE-update digests and falsely reported every updated app as corrupt.
TEST_CASE("repair is healthy after an update (install/update commit parity)") {
    UpdaterFixture fx;
    // Install 1.0.0 through the REAL installer so its per-version meta store
    // exists (install_baseline is a hand-laid shortcut that skips it; a real
    // deployment always goes through Installer::install). The manifest's
    // updates block points at fx.update_url, so the updater can find the
    // update afterwards.
    lexe::Installer installer(fx.paths);
    installer.install(fx.build_package("1.0.0", fx.key), lexe::InstallOptions{});
    REQUIRE(fx.registry.current_version(fx.id) == "1.0.0");

    fx.publish_update("2.0.0", fx.key);
    fx.updater.apply(fx.id);
    REQUIRE(fx.registry.current_version(fx.id) == "2.0.0");

    // The commit bookkeeping the updater used to skip now exists for 2.0.0.
    const fs::path app_dir = fx.registry.app_dir(fx.id);
    CHECK(fs::is_regular_file(app_dir / "meta" / "2.0.0" / "hashes.json"));
    CHECK(fs::is_regular_file(app_dir / "meta" / "2.0.0" / "lexe.json"));
    // The active hashes.json describes the NEW version (not the pre-update one).
    CHECK(lexe::util::slurp(app_dir / "hashes.json") ==
          lexe::util::slurp(app_dir / "meta" / "2.0.0" / "hashes.json"));

    // Repair on a byte-perfect updated install reports healthy (was: exit-3
    // false corruption).
    const lexe::RepairReport report = installer.repair(fx.id);
    CHECK(report.ok);
    CHECK(report.corrupt_files.empty());

    // And repair still works after rolling back to the updated-then-retained
    // 1.0.0 (rollback restores its meta copies).
    installer.rollback(fx.id);
    REQUIRE(fx.registry.current_version(fx.id) == "1.0.0");
    const lexe::RepairReport rolled = installer.repair(fx.id);
    CHECK(rolled.ok);
}

TEST_CASE("tampered update.json signature is refused (check 1)") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");
    const fs::path new_pkg = fx.build_package("2.0.0", fx.key, "", fx.server);

    SUBCASE("signed by a different key") {
        const lexe::crypto::KeyPair attacker = lexe::test::make_keypair();
        fx.serve_update_json(fx.update_json_text("2.0.0", new_pkg), attacker);
        CHECK_THROWS_WITH_AS(fx.updater.check(fx.id),
                             doctest::Contains("check 1"),
                             lexe::VerificationError);
        CHECK_THROWS_WITH_AS(fx.updater.apply(fx.id),
                             doctest::Contains("check 1"),
                             lexe::VerificationError);
    }

    SUBCASE("update.json modified after signing") {
        fx.serve_update_json(fx.update_json_text("2.0.0", new_pkg), fx.key);
        std::string text =
            lexe::util::slurp_text(fx.server / "update.json");
        const std::size_t at = text.find("2.0.0");
        REQUIRE(at != std::string::npos);
        text[at] = '9'; // now advertises 9.0.0, but the signature is stale
        lexe::util::spit(fx.server / "update.json", std::string_view(text));
        CHECK_THROWS_WITH_AS(fx.updater.check(fx.id),
                             doctest::Contains("check 1"),
                             lexe::VerificationError);
    }

    SUBCASE("signature file is not 64 bytes") {
        fx.serve_update_json(fx.update_json_text("2.0.0", new_pkg), fx.key);
        lexe::util::spit(fx.server / "update.json.sig",
                         std::string_view("short"));
        CHECK_THROWS_WITH_AS(fx.updater.check(fx.id),
                             doctest::Contains("64-byte"),
                             lexe::VerificationError);
    }

    SUBCASE("detached signature missing entirely") {
        fx.serve_update_json(fx.update_json_text("2.0.0", new_pkg), fx.key);
        fs::remove(fx.server / "update.json.sig");
        CHECK_THROWS_AS(fx.updater.check(fx.id), lexe::NotFoundError);
    }

    // Nothing may have changed in any subcase.
    CHECK(fx.registry.current_version(fx.id) == "1.0.0");
    CHECK_FALSE(fs::exists(fx.registry.version_dir(fx.id, "2.0.0")));
}

TEST_CASE("update manifest for a different application id is refused (check 2)") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");
    const fs::path new_pkg = fx.build_package("2.0.0", fx.key, "", fx.server);
    // Properly signed, but describes another application.
    fx.serve_update_json(
        fx.update_json_text("2.0.0", new_pkg, "stable", "com.example.other"),
        fx.key);

    CHECK_THROWS_WITH_AS(fx.updater.check(fx.id), doctest::Contains("check 2"),
                         lexe::VerificationError);
    CHECK_THROWS_WITH_AS(fx.updater.apply(fx.id), doctest::Contains("check 2"),
                         lexe::VerificationError);
    CHECK(fx.registry.current_version(fx.id) == "1.0.0");
}

TEST_CASE("missing channel entry is refused (check 3)") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0"); // configured channel: stable
    const fs::path new_pkg = fx.build_package("2.0.0", fx.key, "", fx.server);

    SUBCASE("update.json only serves another channel") {
        fx.serve_update_json(fx.update_json_text("2.0.0", new_pkg, "beta"),
                             fx.key);
        CHECK_THROWS_WITH_AS(fx.updater.check(fx.id),
                             doctest::Contains("check 3"),
                             lexe::VerificationError);
    }

    SUBCASE("update.json has no channels object at all") {
        fx.serve_update_json(
            "{\n  \"lexeVersion\": \"0.1\",\n  \"id\": \"" + fx.id + "\"\n}\n",
            fx.key);
        CHECK_THROWS_WITH_AS(fx.updater.check(fx.id),
                             doctest::Contains("check 3"),
                             lexe::VerificationError);
    }

    SUBCASE("update.json is not valid JSON (verified signature, bad body)") {
        fx.serve_update_json("this is { not json", fx.key);
        CHECK_THROWS_WITH_AS(fx.updater.check(fx.id),
                             doctest::Contains("not valid JSON"),
                             lexe::VerificationError);
    }

    CHECK(fx.registry.current_version(fx.id) == "1.0.0");
}

TEST_CASE("wrong package sha256 is refused (check 4)") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");
    const fs::path new_pkg = fx.build_package("2.0.0", fx.key, "", fx.server);

    SUBCASE("update.json declares a different digest") {
        fx.serve_update_json(
            fx.update_json_text("2.0.0", new_pkg, "stable", "",
                                std::string(64, '0')),
            fx.key);
        // checks 1-3 pass, so the dry-run check succeeds...
        CHECK(fx.updater.check(fx.id).update_available);
        // ...but apply refuses the download at check 4.
        CHECK_THROWS_WITH_AS(fx.updater.apply(fx.id),
                             doctest::Contains("check 4"),
                             lexe::VerificationError);
    }

    SUBCASE("package tampered after update.json was published") {
        fx.serve_update_json(fx.update_json_text("2.0.0", new_pkg), fx.key);
        lexe::test::tamper_entry(new_pkg, "payload/data.txt",
                                 [](std::vector<std::uint8_t>& bytes) {
                                     REQUIRE_FALSE(bytes.empty());
                                     bytes[0] ^= 0x01;
                                 });
        CHECK_THROWS_WITH_AS(fx.updater.apply(fx.id),
                             doctest::Contains("check 4"),
                             lexe::VerificationError);
    }

    CHECK(fx.registry.current_version(fx.id) == "1.0.0");
    CHECK_FALSE(fs::exists(fx.registry.version_dir(fx.id, "2.0.0")));
}

TEST_CASE("package that fails the section-6 pipeline is refused (check 5)") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");
    const fs::path new_pkg = fx.build_package("2.0.0", fx.key, "", fx.server);
    // Break the packaged manifest signature, then advertise the tampered
    // file with its *correct* (post-tamper) sha256 so check 4 passes and the
    // failure is attributed to the §6 pipeline.
    lexe::test::tamper_entry(new_pkg, "signatures/manifest.sig",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE(bytes.size() == 64);
                                 bytes[0] ^= 0x01;
                             });
    fx.serve_update_json(fx.update_json_text("2.0.0", new_pkg), fx.key);

    CHECK_THROWS_WITH_AS(fx.updater.apply(fx.id), doctest::Contains("check 5"),
                         lexe::VerificationError);
    CHECK(fx.registry.current_version(fx.id) == "1.0.0");
    CHECK_FALSE(fs::exists(fx.registry.version_dir(fx.id, "2.0.0")));
}

TEST_CASE("package signed by a different publisher key is refused (check 6)") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");

    SUBCASE("self-consistent package under an attacker key") {
        const lexe::crypto::KeyPair attacker = lexe::test::make_keypair();
        // The package verifies against its own embedded key (§6 passes) and
        // update.json is signed with the *installed* key with the correct
        // sha256 — only the §7 check 6 key pin catches the swap.
        const fs::path evil =
            fx.build_package("2.0.0", attacker, "", fx.server);
        fx.serve_update_json(fx.update_json_text("2.0.0", evil), fx.key);
        CHECK(fx.updater.check(fx.id).update_available); // checks 1-3 pass
        CHECK_THROWS_WITH_AS(fx.updater.apply(fx.id),
                             doctest::Contains("check 6"),
                             lexe::VerificationError);
    }

    SUBCASE("package carries a different application id") {
        const fs::path other =
            fx.build_package("2.0.0", fx.key, "com.example.impostor",
                             fx.server);
        fx.serve_update_json(fx.update_json_text("2.0.0", other), fx.key);
        CHECK_THROWS_WITH_AS(fx.updater.apply(fx.id),
                             doctest::Contains("check 6"),
                             lexe::VerificationError);
    }

    CHECK(fx.registry.current_version(fx.id) == "1.0.0");
    CHECK_FALSE(fs::exists(fx.registry.version_dir(fx.id, "2.0.0")));
}

TEST_CASE("downgrade attempt is refused (check 7)") {
    UpdaterFixture fx;
    fx.install_baseline("2.0.0");
    const fs::path old_pkg = fx.build_package("1.0.0", fx.key, "", fx.server);

    SUBCASE("channel openly advertises an older version") {
        fx.serve_update_json(fx.update_json_text("1.0.0", old_pkg), fx.key);
        const lexe::UpdateCheck chk = fx.updater.check(fx.id);
        CHECK(chk.installed_version == "2.0.0");
        CHECK(chk.available_version == "1.0.0");
        CHECK_FALSE(chk.update_available);
        CHECK_THROWS_WITH_AS(fx.updater.apply(fx.id),
                             doctest::Contains("downgrade refused"),
                             lexe::VerificationError);
    }

    SUBCASE("channel lies newer but the package itself is older") {
        // Advertised 3.0.0, but the url/sha256 point at the 1.0.0 package:
        // checks 4-6 all pass; check 7 must still catch the actual version.
        fx.serve_update_json(fx.update_json_text("3.0.0", old_pkg), fx.key);
        CHECK(fx.updater.check(fx.id).update_available); // the lie looks new
        CHECK_THROWS_WITH_AS(fx.updater.apply(fx.id),
                             doctest::Contains("downgrade refused"),
                             lexe::VerificationError);
    }

    CHECK(fx.registry.current_version(fx.id) == "2.0.0");
    CHECK_FALSE(fs::exists(fx.registry.version_dir(fx.id, "1.0.0")));
    CHECK(fx.registry.read_record(fx.id).version == "2.0.0");
}

TEST_CASE("equal version is an already-up-to-date no-op") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");
    const fs::path same = fx.build_package("1.0.0", fx.key, "", fx.server);
    fx.serve_update_json(fx.update_json_text("1.0.0", same), fx.key);

    const lexe::UpdateCheck chk = fx.updater.check(fx.id);
    CHECK(chk.installed_version == "1.0.0");
    CHECK(chk.available_version == "1.0.0");
    CHECK_FALSE(chk.update_available);

    // Not newer is not an attack: a plain Error, not a VerificationError.
    bool threw_plain_error = false;
    try {
        fx.updater.apply(fx.id);
    } catch (const lexe::VerificationError&) {
        FAIL("equal version must not be reported as a verification failure");
    } catch (const lexe::Error& e) {
        threw_plain_error = true;
        CHECK(std::string(e.what()).find("already up to date") !=
              std::string::npos);
    }
    CHECK(threw_plain_error);

    // Strictly a no-op.
    CHECK(fx.registry.current_version(fx.id) == "1.0.0");
    CHECK(fx.registry.read_record(fx.id).version == "1.0.0");
    CHECK(fx.registry.installed_versions(fx.id).size() == 1);
}

TEST_CASE("set_source records the new source and it becomes the default") {
    UpdaterFixture fx;
    fx.install_baseline("1.0.0");
    // The original server never publishes anything.
    CHECK_THROWS_AS(fx.updater.check(fx.id), lexe::NotFoundError);

    // A mirror the user explicitly chooses (SPEC "Installation Sources").
    const fs::path mirror = fx.home.path() / "mirror";
    fs::create_directories(mirror);
    const std::string mirror_url = to_file_url(mirror / "update.json");
    const fs::path new_pkg = fx.build_package("2.0.0", fx.key, "", mirror);
    fx.serve_update_json(fx.update_json_text("2.0.0", new_pkg), fx.key,
                         mirror);

    fx.updater.set_source(fx.id, mirror_url);
    CHECK(fx.registry.read_record(fx.id).update_url == mirror_url);

    // Checks and updates now flow from the chosen source...
    const lexe::UpdateCheck chk = fx.updater.check(fx.id);
    CHECK(chk.available_version == "2.0.0");
    CHECK(chk.update_available);
    fx.updater.apply(fx.id);
    CHECK(fx.registry.current_version(fx.id) == "2.0.0");
    // ...and the chosen source stays the default after the update (SPEC:
    // "The user's chosen source becomes the default update source").
    CHECK(fx.registry.read_record(fx.id).update_url == mirror_url);

    SUBCASE("set_source rejects an empty URL") {
        CHECK_THROWS_AS(fx.updater.set_source(fx.id, ""), lexe::UsageError);
    }
}

TEST_CASE("missing app, missing source and missing update.json") {
    UpdaterFixture fx;

    SUBCASE("application not installed") {
        CHECK_THROWS_AS(fx.updater.check("com.example.absent"),
                        lexe::NotFoundError);
        CHECK_THROWS_AS(fx.updater.apply("com.example.absent"),
                        lexe::NotFoundError);
        CHECK_THROWS_AS(fx.updater.set_source("com.example.absent",
                                              "file:///tmp/update.json"),
                        lexe::NotFoundError);
    }

    SUBCASE("installed but no update source configured") {
        fx.install_baseline("1.0.0");
        lexe::InstallationRecord record = fx.registry.read_record(fx.id);
        record.update_url = "";
        fx.registry.write_record(record);
        CHECK_THROWS_AS(fx.updater.check(fx.id), lexe::NotFoundError);
        CHECK_THROWS_AS(fx.updater.apply(fx.id), lexe::NotFoundError);
    }

    SUBCASE("source configured but update.json absent on the server") {
        fx.install_baseline("1.0.0");
        CHECK_THROWS_AS(fx.updater.check(fx.id), lexe::NotFoundError);
        CHECK(fx.registry.current_version(fx.id) == "1.0.0");
    }
}

} // TEST_SUITE("updater")

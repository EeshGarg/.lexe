// permission vocabulary / normalization / digest / delta tests (runtime-trust
// WS2/WS5). Proves unknown, duplicate and (reserved) conflicting permissions
// are rejected; the digest is order-independent and stable; and the delta
// classifies added / removed / unchanged and flags expansions.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/permissions.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;

namespace {
// Pack a package for `id` requesting `perms`, signed with `key`.
fs::path pack_with_perms(const fs::path& work, const crypto::KeyPair& key,
                         const std::string& id,
                         const std::vector<std::string>& perms,
                         const std::string& version = "1.0.0") {
    test::TestAppSpec spec;
    spec.id = id;
    spec.version = version;
    spec.public_key = test::encode_public_key_str(key.public_key);
    test::TestAppTree tree =
        test::make_test_app_tree(work / ("t-" + id + "-" + version), spec);
    nlohmann::json m =
        nlohmann::json::parse(util::slurp_text(tree.manifest_file));
    m["permissions"] = perms;
    util::spit(tree.manifest_file, std::string_view(m.dump(2) + "\n"));
    PackageWriter::Inputs in;
    in.payload_dir = tree.payload_dir;
    in.manifest_file = tree.manifest_file;
    const fs::path out = work / (id + "-" + version + ".lexe");
    PackageWriter::write(in, key, out);
    return out;
}
} // namespace

TEST_SUITE("permissions") {

TEST_CASE("the vocabulary is frozen and looked up by id") {
    // Exactly the two 0.1 permissions, each with defined semantics.
    CHECK(permission_vocabulary().size() == 2);
    CHECK(find_permission("network") != nullptr);
    CHECK(find_permission("user-files-selected") != nullptr);
    CHECK(find_permission("nonsense") == nullptr);
    // Enforcement ceilings are honest: network is enforceable, file access is
    // advisory in 0.1.
    CHECK(find_permission("network")->baseline == PermissionBaseline::Enforceable);
    CHECK(find_permission("user-files-selected")->baseline ==
          PermissionBaseline::Advisory);
}

TEST_CASE("normalization accepts known permissions and canonicalizes order") {
    const NormalizedPermissions a =
        normalize_permissions({"network", "user-files-selected"});
    const NormalizedPermissions b =
        normalize_permissions({"user-files-selected", "network"});
    // Order-independent: same ids, same digest.
    CHECK(a.ids == std::vector<std::string>{"network", "user-files-selected"});
    CHECK(a.ids == b.ids);
    CHECK(a.digest == b.digest);
    CHECK(a.digest.rfind("sha256:", 0) == 0);

    // The empty set is valid and has its own stable digest.
    const NormalizedPermissions e = normalize_permissions({});
    CHECK(e.ids.empty());
    CHECK(e.digest != a.digest);
}

TEST_CASE("unknown and duplicate permissions are rejected") {
    CHECK_THROWS_WITH_AS(normalize_permissions({"network", "root"}),
                         doctest::Contains("unknown permission"),
                         lexe::VerificationError);
    CHECK_THROWS_WITH_AS(normalize_permissions({"network", "network"}),
                         doctest::Contains("duplicate permission"),
                         lexe::VerificationError);
    // A package must not smuggle an expansion via an alias/casing.
    CHECK_THROWS_AS(normalize_permissions({"Network"}), lexe::VerificationError);
    CHECK_THROWS_AS(normalize_permissions({"network:all"}),
                    lexe::VerificationError);
}

TEST_CASE("normalized_from_ids re-validates and recomputes the digest") {
    // A stored approved set is re-validated (a tampered id is rejected) and its
    // digest recomputed, so a forged digest cannot be trusted.
    const NormalizedPermissions n = normalized_from_ids({"network"});
    CHECK(n.digest == normalize_permissions({"network"}).digest);
    CHECK_THROWS_AS(normalized_from_ids({"totally-made-up"}),
                    lexe::VerificationError);
}

TEST_CASE("permission delta classifies added / removed / unchanged") {
    const NormalizedPermissions approved = normalize_permissions({"network"});
    const NormalizedPermissions expand =
        normalize_permissions({"network", "user-files-selected"});
    const NormalizedPermissions shrink = normalize_permissions({});
    const NormalizedPermissions same = normalize_permissions({"network"});

    const PermissionDelta d_expand = permission_delta(approved, expand);
    CHECK(d_expand.added == std::vector<std::string>{"user-files-selected"});
    CHECK(d_expand.unchanged == std::vector<std::string>{"network"});
    CHECK(d_expand.removed.empty());
    CHECK(d_expand.expands());

    const PermissionDelta d_shrink = permission_delta(approved, shrink);
    CHECK(d_shrink.removed == std::vector<std::string>{"network"});
    CHECK(d_shrink.added.empty());
    CHECK_FALSE(d_shrink.expands());

    const PermissionDelta d_same = permission_delta(approved, same);
    CHECK(d_same.added.empty());
    CHECK(d_same.removed.empty());
    CHECK(d_same.unchanged == std::vector<std::string>{"network"});
    CHECK_FALSE(d_same.expands());

    // Reordering the candidate must not produce a false delta.
    const NormalizedPermissions reordered =
        normalize_permissions({"user-files-selected", "network"});
    const PermissionDelta d_reorder = permission_delta(expand, reordered);
    CHECK_FALSE(d_reorder.expands());
    CHECK(d_reorder.added.empty());
    CHECK(d_reorder.removed.empty());
}

TEST_CASE("install persists the approved permission set and digest") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);

    const fs::path pkg =
        pack_with_perms(work, key, "com.example.net", {"network"});
    Installer(paths).install(pkg, InstallOptions{});

    const InstallationRecord rec = Registry(paths).read_record("com.example.net");
    CHECK(rec.approved_permissions == std::vector<std::string>{"network"});
    CHECK(rec.permissions_digest == normalize_permissions({"network"}).digest);
}

TEST_CASE("install refuses a package requesting an unknown permission") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);

    const fs::path pkg =
        pack_with_perms(work, key, "com.example.bad", {"network", "be-root"});
    CHECK_THROWS_WITH_AS(Installer(paths).install(pkg, InstallOptions{}),
                         doctest::Contains("unknown permission"),
                         lexe::VerificationError);
    CHECK_FALSE(Registry(paths).is_installed("com.example.bad"));
}

TEST_CASE("an update that EXPANDS permissions is refused without consent (WS5)") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const std::string id = "com.example.grow";

    // Install 1.0.0 approving only {network}.
    Installer(paths).install(pack_with_perms(work, key, id, {"network"}, "1.0.0"),
                             InstallOptions{});

    // 2.0.0 adds user-files-selected — refused with PermissionError (exit 5),
    // and the previous version stays active.
    const fs::path v2 =
        pack_with_perms(work, key, id, {"network", "user-files-selected"}, "2.0.0");
    CHECK_THROWS_WITH_AS(Installer(paths).install(v2, InstallOptions{}),
                         doctest::Contains("new permissions"),
                         lexe::PermissionError);
    CHECK(exit_code_for(lexe::PermissionError("x")) == 5);
    CHECK(Registry(paths).current_version(id) == "1.0.0");
    CHECK(Registry(paths).read_record(id).approved_permissions ==
          std::vector<std::string>{"network"});

    // With explicit consent it proceeds and the approved set is updated.
    InstallOptions opts;
    opts.allow_permission_expansion = true;
    Installer(paths).install(v2, opts);
    CHECK(Registry(paths).current_version(id) == "2.0.0");
    CHECK(Registry(paths).read_record(id).approved_permissions ==
          std::vector<std::string>{"network", "user-files-selected"});
}

TEST_CASE("updates that REMOVE or keep permissions need no extra consent (WS5)") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const std::string id = "com.example.same";

    Installer(paths).install(
        pack_with_perms(work, key, id, {"network", "user-files-selected"}, "1.0.0"),
        InstallOptions{});
    // 2.0.0 drops user-files-selected — a reduction, allowed without consent.
    Installer(paths).install(
        pack_with_perms(work, key, id, {"network"}, "2.0.0"), InstallOptions{});
    CHECK(Registry(paths).current_version(id) == "2.0.0");
    // 3.0.0 keeps the same single permission — no delta, allowed.
    Installer(paths).install(
        pack_with_perms(work, key, id, {"network"}, "3.0.0"), InstallOptions{});
    CHECK(Registry(paths).current_version(id) == "3.0.0");
}

} // TEST_SUITE("permissions")

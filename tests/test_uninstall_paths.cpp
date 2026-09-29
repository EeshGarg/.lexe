// "Installer-owned cleanup cannot delete arbitrary paths."
//
// docs/HARDENING.md lists this among the proven security invariants. Its
// Proven-by column read: `test_invariants` (uninstall spares other apps),
// `transaction.cpp` review.
//
// The test it named checks that uninstalling one application leaves a second
// one installed. True, and much weaker than the invariant, which says every
// deletion target is validated and "never a path from package content".
//
// `Installer::uninstall` ends with a sweep over `record.created_files` --
// absolute paths read out of `installation.json` -- and it had no containment
// check at all:
//
//     for (const std::string& file : record.created_files)
//         util::remove_recursive(fs::path(file));
//
// Measured before the fix: two paths appended to that record, an ordinary
// directory and an ordinary file well outside LEXE_HOME, and `lexe remove`
// destroyed both -- the directory RECURSIVELY -- while printing a clean
// removal.
//
// What makes it worth a test rather than a one-line fix is that this is the
// SECOND time. `may_delete` in integration.cpp exists because the same bug was
// found there: artifact records pointing into $HOME, deleted by
// `doctor --repair`. That fix was applied to the module where it was
// demonstrated and not to this one, which reads a different file for the same
// purpose. A guard only one caller honours is a convention, not an invariant,
// and this file is what turns it back into one.
//
// It is not a privilege boundary -- whoever can write the record can usually
// delete these files directly -- and the likelier cause is not malice but a
// truncated or garbled record with a mangled path reaching a recursive delete.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/paths.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/package/package.hpp"
#include "lexe/state/registry.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

const char* kId = "com.example.sweep";

fs::path build_pkg(const fs::path& work, const crypto::KeyPair& key) {
    test::TestAppSpec spec;
    spec.id = kId;
    spec.version = "1.0.0";
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree = test::make_test_app_tree(work / "tree", spec);
    PackageWriter::Inputs in;
    in.payload_dir = tree.payload_dir;
    in.manifest_file = tree.manifest_file;
    const fs::path out = work / "sweep.lexe";
    PackageWriter::write(in, key, out);
    return out;
}

void write_file(const fs::path& p, const std::string& text) {
    fs::create_directories(p.parent_path());
    std::ofstream(p) << text;
}

} // namespace

TEST_SUITE("uninstall_paths") {

TEST_CASE("uninstall refuses to delete a recorded path outside the runtime's "
          "own directories") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();

    Installer installer(paths);
    installer.install(build_pkg(work, key), InstallOptions{});
    REQUIRE(Registry(paths).is_installed(kId));

    // Two bystanders with nothing to do with .LEXE: one directory (to catch
    // the recursive delete specifically) and one plain file.
    const fs::path outsider_dir = work / "precious";
    const fs::path outsider_file = work / "single.txt";
    write_file(outsider_dir / "notes.txt", "do not delete me\n");
    write_file(outsider_file, "nor me\n");

    // And one path the runtime legitimately owns, to serve as the control.
    const fs::path owned = paths.launch_dir() / "sweep-control.lexe";
    write_file(owned, "runtime-owned\n");

    // Append all three to the installation record, exactly as the reproducer
    // did. This is local unsigned state; writing it is the whole point.
    const fs::path record = Registry(paths).app_dir(kId) / "installation.json";
    REQUIRE(fs::exists(record));
    {
        std::ifstream in(record);
        nlohmann::json doc = nlohmann::json::parse(in);
        const char* field = doc.contains("createdFiles") ? "createdFiles"
                                                         : "created_files";
        doc[field].push_back(outsider_dir.string());
        doc[field].push_back(outsider_file.string());
        doc[field].push_back(owned.string());
        std::ofstream(record) << doc.dump(2);
    }

    installer.uninstall(kId);

    // The invariant.
    CHECK(fs::exists(outsider_dir / "notes.txt"));
    CHECK(fs::exists(outsider_file));

    // The control, and it is not optional. Without it this test passes against
    // an uninstall that deletes NOTHING -- including the desktop files it is
    // supposed to clean up -- which would look like a fix and be a regression.
    // Asserting that the runtime-owned path IS gone is what distinguishes
    // "confined" from "broken".
    CHECK_FALSE(fs::exists(owned));

    // Refusals are reported, not swallowed: a record naming a path outside the
    // tree is itself a finding.
    const std::vector<std::string>& refused = installer.refused_paths();
    const auto named = [&](const fs::path& p) {
        return std::find(refused.begin(), refused.end(), p.string()) !=
               refused.end();
    };
    CHECK(named(outsider_dir));
    CHECK(named(outsider_file));
    CHECK_FALSE(named(owned)); // deleted, so nothing to report

    // And the application itself really is gone -- the refusals must not have
    // aborted the uninstall.
    CHECK_FALSE(Registry(paths).is_installed(kId));
}

} // TEST_SUITE("uninstall_paths")

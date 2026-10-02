// uninstall versus purge -- the removal contract, observed from outside.
//
//   lexe uninstall <id>   remove the installed program; keep what makes a
//                         reinstall a RETURNING installation
//   lexe purge <id>       make .LEXE forget the application
//
// The contract lives in one table (src/lexe/state/appstate.cpp) and the code
// that implements it reads that table. So these tests deliberately do NOT
// derive their verdict from it alone: every case also WALKS the whole LEXE_HOME
// and collects every path whose name carries the App ID. A location the table
// forgot would satisfy every table-driven check and still be on disk; the walk
// is what would see it. A check cannot detect what it holds constant.
//
// The purge invariant (docs/REFERENCE-POLICY.md, "Uninstall and purge"):
//
//   After a successful `lexe purge A`, no .LEXE-managed state associated
//   exclusively with A can affect a later installation, verification,
//   authorization, configuration or execution of A.
//
// "First-install path" is observed the way install itself decides it: the
// trust evaluation install performs, with the retained-data owner read from
// disk exactly as install reads it.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/error.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/base/util.hpp"
#include "lexe/diagnostics/diagnostics.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/integration/integration.hpp"
#include "lexe/runtime/launcher.hpp"
#include "lexe/state/appconfig.hpp"
#include "lexe/state/appstate.hpp"
#include "lexe/state/lock.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/verify/trust.hpp"

#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace lexe;

namespace {

const char* kA = "com.example.purge";
// Shares A's publisher key AND has A's App ID as a prefix -- the two ways a
// careless purge of A could reach it: by key, or by name. Its lease file
// `com.example.purge.v.2.v.1.0.0.lease` matches a `com.example.purge.v.*` glob.
// Not `.v.1`: A's OWN lease, `com.example.purge.v.1.0.0.lease`, contains that
// string, and the walk below would then attribute A's file to B -- the
// ambiguity appstate.hpp describes, reproduced in the observer.
const char* kB = "com.example.purge.v.2";

struct ScopedFault {
    explicit ScopedFault(const std::string& site) {
        util::set_env("LEXE_TEST_FAULT", site);
    }
    ~ScopedFault() { util::unset_env("LEXE_TEST_FAULT"); }
};

/// Packages are built OUTSIDE LEXE_HOME: their file names carry the App ID and
/// would otherwise be found by the walk below.
struct Work {
    fs::path dir = test::unique_temp_dir("lexe-purge-work-");
    Work() { fs::create_directories(dir); }
    ~Work() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

fs::path package_for(const fs::path& work, const crypto::KeyPair& key,
                     const std::string& id, const std::string& version = "1.0.0") {
    test::TestAppSpec spec;
    spec.id = id;
    spec.version = version;
    return test::make_test_package(work, key, spec);
}

/// The INDEPENDENT observer: every entry under `root` whose name contains
/// `needle` (and not `exclude`), reported at the shallowest such level, as a
/// path relative to root. Reads the disk, not the table.
std::set<std::string> walk(const fs::path& root, const std::string& needle,
                           const std::string& exclude = "") {
    std::set<std::string> out;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(
             root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        const std::string name = it->path().filename().string();
        if (name.find(needle) == std::string::npos) continue;
        if (!exclude.empty() && name.find(exclude) != std::string::npos) continue;
        out.insert(fs::relative(it->path(), root).generic_string());
        it.disable_recursion_pending();
    }
    return out;
}

/// The table's locations with the given fates, relative to `root`.
std::set<std::string> expected(const Paths& paths, const std::string& id,
                               std::initializer_list<StateFate> fates) {
    std::set<std::string> out;
    for (const AppStateEntry& e : app_state_table(paths, id)) {
        for (StateFate f : fates) {
            if (e.fate == f) {
                out.insert(fs::relative(e.path, paths.home()).generic_string());
            }
        }
    }
    return out;
}

/// The trust decision `install` would reach for `id` signed by `key`, with the
/// retained-data owner read from disk the way install reads it.
TrustEvaluation evaluate_like_install(const Paths& paths, const std::string& id,
                                      const crypto::KeyPair& key) {
    const Registry registry(paths);
    std::optional<std::string> owner;
    const fs::path marker = registry.data_owner_marker(id);
    if (fs::is_regular_file(marker)) {
        std::string s = util::slurp_text(marker);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r' ||
                              s.back() == ' ')) {
            s.pop_back();
        }
        if (!s.empty()) owner = s;
    }
    return TrustStore(paths).evaluate(id, key.public_key, SignatureState::Valid,
                                      owner);
}

/// Install `id` with an EXPLICIT trust decision and give it one of every kind
/// of per-app state: data, a compatibility preference, an error record, cache,
/// a downloaded update and a version lease file.
void install_with_state(const Paths& paths, const fs::path& pkg,
                        const std::string& id) {
    InstallOptions o;
    o.explicit_trust = true;
    Installer(paths).install(pkg, o);
    const Registry registry(paths);
    util::spit(registry.app_data_dir(id) / "save.dat",
               std::string_view("precious save"));
    AppConfig config;
    config.id = id;
    config.compatibility_mode = CompatibilityMode::Manual;
    config.preferred_chain = {"native"};
    config.save(paths);
    ErrorRecord rec;
    rec.application_id = id;
    rec.application_version = "1.0.0";
    rec.summary = "an earlier failure";
    REQUIRE_FALSE(ErrorStore(paths).record(rec).record_path.empty());
    util::spit(registry.app_cache_dir(id) / "thumb.png", std::string_view("c"));
    util::spit(paths.cache_dir() / "updates" / id / "package.lexe",
               std::string_view("d"));
    util::spit(registry.version_lease_file(id, "1.0.0"), std::string_view(""));
}

/// The installation is ENTIRELY absent: no record, no directory, no
/// integration, no cache, no debris.
void check_installation_gone(const Paths& paths, const std::string& id) {
    const Registry registry(paths);
    CHECK_FALSE(registry.is_installed(id));
    CHECK_FALSE(fs::exists(registry.app_dir(id)));
    CHECK(IntegrationState::load(paths).scope(id).empty());
    CHECK_FALSE(fs::exists(registry.app_cache_dir(id)));
    CHECK_FALSE(fs::exists(paths.cache_dir() / "updates" / id));
    CHECK_FALSE(fs::exists(registry.version_lease_file(id, "1.0.0")));
}

/// Never "files gone and installed=true": an application that reports as
/// installed has its active version on disk and passes its health check.
void check_never_half_installed(const Paths& paths, const std::string& id) {
    const Registry registry(paths);
    if (!registry.is_installed(id)) return;
    const std::string current = registry.current_version(id);
    CHECK(fs::is_directory(registry.version_dir(id, current)));
    CHECK(Installer(paths).check_health(id).ok);
}

} // namespace

TEST_SUITE("purge") {

TEST_CASE("the table's error-history path is the one ErrorStore writes") {
    // appstate (state/) may not include diagnostics/, which sits above it in
    // the layering, so it derives this path from base/'s root. This is what
    // keeps that derivation honest.
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    bool found = false;
    for (const AppStateEntry& e : app_state_table(paths, kA)) {
        if (e.what == "error history") {
            CHECK(e.path == ErrorStore(paths).app_dir(kA));
            found = true;
        }
    }
    CHECK(found);
    // And every root the walk below relies on really is under LEXE_HOME.
    for (const fs::path& root :
         {paths.cache_dir(), paths.state_dir(), paths.config_dir(),
          paths.applications_dir(), paths.icons_dir(), paths.mime_dir()}) {
        CAPTURE(root.string());
        CHECK(fs::relative(root, paths.home()).generic_string().rfind("..", 0) != 0);
    }
}

TEST_CASE("every location in the table is documented, word for word") {
    // docs/REFERENCE-POLICY.md, "Uninstall and purge", is the contract a user
    // reads; the table is the contract the code runs. An entry added to one
    // and not the other is a contract that says one thing and does another.
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const std::string doc = util::slurp_text(
        fs::path(LEXE_SOURCE_DIR) / "docs" / "REFERENCE-POLICY.md");
    REQUIRE_FALSE(doc.empty());
    for (const AppStateEntry& e : app_state_table(paths, kA)) {
        CAPTURE(e.what);
        CHECK(doc.find("| " + e.what + " |") != std::string::npos);
    }
    // And the invariant itself is stated there.
    CHECK(doc.find("After a successful `lexe purge A`, no .LEXE-managed state")
          != std::string::npos);
}

TEST_CASE("CASE 1: uninstall keeps exactly the documented returning state") {
    test::TempLexeHome home;
    Work work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = package_for(work.dir, key, kA);
    install_with_state(paths, pkg, kA);
    const TrustRecord before = *TrustStore(paths).read(kA);
    REQUIRE(before.explicitly_trusted);

    Installer(paths).uninstall(kA);

    check_installation_gone(paths, kA);
    // ONLY the documented survivors, by the independent walk: persistent data,
    // trust record, preferences, error history -- and the inert mutation lock.
    CHECK(walk(paths.home(), kA) ==
          expected(paths, kA, {StateFate::SurvivesUninstall, StateFate::Kept}));

    // A reinstall is a RETURNING one: the known key, explicitly trusted ...
    const TrustEvaluation eval = evaluate_like_install(paths, kA, key);
    CHECK(eval.key_state == PublisherKeyState::ExplicitlyTrusted);
    CHECK(eval.decision == TrustDecision::AllowKnownUpdate);
    CHECK_FALSE(eval.needs_first_install_consent());

    // ... and after it, everything that survived is in force again.
    Installer(paths).install(pkg); // a PLAIN install: no new explicit trust
    const TrustRecord after = *TrustStore(paths).read(kA);
    CHECK(after.explicitly_trusted);               // the old decision stands
    CHECK(after.first_seen == before.first_seen);  // the same history
    CHECK(util::slurp_text(registry.app_data_dir(kA) / "save.dat") ==
          "precious save");
    CHECK(AppConfig::load(paths, kA).compatibility_mode ==
          CompatibilityMode::Manual);
    CHECK_FALSE(ErrorStore(paths).history(kA).empty());
}

TEST_CASE("CASE 2: purge forgets the application; a reinstall is a first install") {
    test::TempLexeHome home;
    Work work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = package_for(work.dir, key, kA);
    install_with_state(paths, pkg, kA);

    SUBCASE("purge of an installed application") {
        const Installer::PurgeReport report = Installer(paths).purge(kA);
        CHECK(report.was_installed);
        CHECK_FALSE(report.finished_interrupted);
    }
    SUBCASE("purge after an uninstall: what uninstall kept is what purge removes") {
        Installer(paths).uninstall(kA);
        const Installer::PurgeReport report = Installer(paths).purge(kA);
        CHECK_FALSE(report.was_installed);
    }

    check_installation_gone(paths, kA);
    CHECK_FALSE(purge_pending(paths, kA));
    // Everything except the inert mutation lock, by the independent walk.
    CHECK(walk(paths.home(), kA) == expected(paths, kA, {StateFate::Kept}));

    // The first-install path: no binding, no retained-data owner, consent
    // required -- exactly what a never-installed App ID gets.
    const TrustEvaluation eval = evaluate_like_install(paths, kA, key);
    CHECK(eval.key_state == PublisherKeyState::FirstSeen);
    CHECK(eval.decision == TrustDecision::AllowFirstInstall);
    CHECK(eval.needs_first_install_consent());
    CHECK_FALSE(eval.explicitly_trusted);

    // And nothing of the old application is in force after reinstalling it.
    Installer(paths).install(pkg);
    const TrustRecord after = *TrustStore(paths).read(kA);
    CHECK_FALSE(after.explicitly_trusted);
    CHECK(after.trust_provenance == "install-accept");
    CHECK_FALSE(fs::exists(registry.app_data_dir(kA) / "save.dat"));
    CHECK(AppConfig::load(paths, kA).compatibility_mode ==
          CompatibilityMode::Automatic);
    CHECK(ErrorStore(paths).history(kA).empty());

    // Nothing left to forget: the never-installed answer.
    Installer(paths).purge(kA);
    CHECK_THROWS_AS(Installer(paths).purge(kA), NotFoundError);
}

TEST_CASE("CASE 2b: purge forgets a local block too, and the block was real") {
    test::TempLexeHome home;
    Work work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = package_for(work.dir, key, kA);
    Installer(paths).install(pkg);
    Installer(paths).uninstall(kA);
    TrustStore(paths).block(kA);

    // The control: the block is in force. Without this, "installs after purge"
    // would pass against a block that never refused anything.
    CHECK_THROWS_AS(Installer(paths).install(pkg), BlockedKeyError);

    Installer(paths).purge(kA);
    CHECK_FALSE(TrustStore(paths).exists(kA));
    CHECK(evaluate_like_install(paths, kA, key).decision ==
          TrustDecision::AllowFirstInstall);
    CHECK_NOTHROW(Installer(paths).install(pkg));
}

TEST_CASE("CASE 3: purging A leaves B -- same key, A's id as its prefix -- alone") {
    test::TempLexeHome home;
    Work work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair(); // K signs BOTH
    install_with_state(paths, package_for(work.dir, key, kA), kA);
    install_with_state(paths, package_for(work.dir, key, kB), kB);
    // A third App ID, blocked locally and never installed: another
    // application's SECURITY decision that purging A must not touch.
    const char* kC = "com.example.blocked";
    TrustStore(paths).block(kC);

    const std::string b_trust = util::slurp_text(registry.trust_record_file(kB));
    const std::set<std::string> b_paths = walk(paths.home(), kB);
    REQUIRE(b_paths.count("locks/" + std::string(kB) + ".v.1.0.0.lease") == 1);

    Installer(paths).purge(kA);

    // A: gone, and back on the first-install path even though K is explicitly
    // trusted for B -- trust is per App ID, not per key.
    CHECK(walk(paths.home(), kA, kB) == expected(paths, kA, {StateFate::Kept}));
    const TrustEvaluation a = evaluate_like_install(paths, kA, key);
    CHECK(a.key_state == PublisherKeyState::FirstSeen);
    CHECK(a.decision == TrustDecision::AllowFirstInstall);

    // B: byte-for-byte untouched -- trust record, every path it owns, its
    // installation, and its lease file, whose name begins with A's App ID.
    CHECK(util::slurp_text(registry.trust_record_file(kB)) == b_trust);
    CHECK(walk(paths.home(), kB) == b_paths);
    CHECK(registry.is_installed(kB));
    CHECK(Installer(paths).check_health(kB).ok);
    const TrustEvaluation b = evaluate_like_install(paths, kB, key);
    CHECK(b.key_state == PublisherKeyState::ExplicitlyTrusted);
    CHECK(b.decision == TrustDecision::AllowKnownUpdate);

    // C: still blocked.
    REQUIRE(TrustStore(paths).read(kC).has_value());
    CHECK(TrustStore(paths).read(kC)->blocked);
}

TEST_CASE("CASE 4: a purge interrupted anywhere finishes, and never half-trusts") {
    struct Site {
        const char* name;
        bool installed_after; // where the interruption leaves the program
    };
    const Site sites[] = {
        {"purge-after-journal", true},
        {"purge-after-detach", false},
        {"purge-after-trust", false},
        {"purge-before-commit", false},
    };
    for (const Site& site : sites) {
        for (const bool recover_by_install : {false, true}) {
            CAPTURE(site.name);
            CAPTURE(recover_by_install);
            test::TempLexeHome home;
            Work work;
            const Paths paths = Paths::detect();
            const Registry registry(paths);
            const crypto::KeyPair key = test::make_keypair();
            const fs::path pkg = package_for(work.dir, key, kA);
            install_with_state(paths, pkg, kA);

            {
                ScopedFault fault(site.name);
                CHECK_THROWS(Installer(paths).purge(kA)); // never "success"
            }

            // Unfinished, and every observable says so.
            CHECK(purge_pending(paths, kA));
            CHECK(registry.is_installed(kA) == site.installed_after);
            check_never_half_installed(paths, kA);
            CHECK_THROWS_AS(Installer(paths).uninstall(kA), BusyError);
            if (site.installed_after) {
                // Still installed, so the launch path is reachable -- and
                // refuses before doing anything.
                RunRequest req;
                req.id = kA;
                CHECK_THROWS_AS(run_application(paths, req), BusyError);
            }

            if (recover_by_install) {
                // install finishes the purge FIRST, then installs from nothing.
                Installer(paths).install(pkg);
                CHECK_FALSE(purge_pending(paths, kA));
                const TrustRecord rec = *TrustStore(paths).read(kA);
                CHECK_FALSE(rec.explicitly_trusted);
                CHECK(rec.trust_provenance == "install-accept");
                CHECK_FALSE(fs::exists(registry.app_data_dir(kA) / "save.dat"));
                CHECK(AppConfig::load(paths, kA).compatibility_mode ==
                      CompatibilityMode::Automatic);
            } else {
                const Installer::PurgeReport report = Installer(paths).purge(kA);
                CHECK(report.finished_interrupted);
                CHECK_FALSE(purge_pending(paths, kA));
                check_installation_gone(paths, kA);
                CHECK(walk(paths.home(), kA) ==
                      expected(paths, kA, {StateFate::Kept}));
                CHECK(evaluate_like_install(paths, kA, key).decision ==
                      TrustDecision::AllowFirstInstall);
            }
        }
    }
}

TEST_CASE("CASE 4b: a purge never reports success over a trust record that came back") {
    // The post-check. A writer outside the purge's lock recreating state in
    // the middle of it is simulated by writing the ORIGINAL, valid trust record
    // back after its deletion -- the worst case: purged, and still trusted.
    test::TempLexeHome home;
    Work work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = package_for(work.dir, key, kA);
    install_with_state(paths, pkg, kA);

    {
        ScopedFault fault("purge-resurrect-trust");
        bool threw = false;
        try {
            Installer(paths).purge(kA);
        } catch (const Error& e) {
            threw = true;
            CHECK(std::string(e.what()).find("did not complete") != std::string::npos);
            CHECK(std::string(e.what()).find("local trust record") != std::string::npos);
        }
        CHECK(threw);
    }
    // Not finished, and the valid record really is there: the post-check saw
    // something true, not something it imagined.
    CHECK(purge_pending(paths, kA));
    REQUIRE(TrustStore(paths).read(kA).has_value());
    CHECK(TrustStore(paths).read(kA)->explicitly_trusted);

    // The NEXT operation finishes it, and the record is gone for good.
    Installer(paths).install(pkg);
    CHECK_FALSE(TrustStore(paths).read(kA)->explicitly_trusted);
}

#ifndef _WIN32
TEST_CASE("CASE 4c: a purge that cannot delete the trust record fails closed") {
    if (::geteuid() == 0) {
        WARN("running as root: a read-only directory does not stop root, so "
             "this case cannot observe a failed deletion here");
        return;
    }
    test::TempLexeHome home;
    Work work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();
    install_with_state(paths, package_for(work.dir, key, kA), kA);
    Installer(paths).uninstall(kA);

    const fs::path trust_dir = registry.trust_record_file(kA).parent_path();
    fs::permissions(trust_dir, fs::perms::owner_read | fs::perms::owner_exec);
    CHECK_THROWS_AS(Installer(paths).purge(kA), Error);
    fs::permissions(trust_dir, fs::perms::owner_all);

    // Reported as a failure, the journal kept, the record still there -- and
    // because the trust record goes FIRST, the data it decides about is
    // untouched too: nothing half-forgotten.
    CHECK(purge_pending(paths, kA));
    CHECK(fs::exists(registry.trust_record_file(kA)));
    CHECK(fs::exists(registry.app_data_dir(kA) / "save.dat"));
    CHECK_THROWS_AS(Installer(paths).uninstall(kA), BusyError);

    const Installer::PurgeReport report = Installer(paths).purge(kA);
    CHECK(report.finished_interrupted);
    CHECK(walk(paths.home(), kA) == expected(paths, kA, {StateFate::Kept}));
}

TEST_CASE("purge refuses a running application before writing anything") {
    test::TempLexeHome home;
    Work work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    install_with_state(paths, package_for(work.dir, key, kA), kA);

    {
        LaunchLease running = make_lock_manager(paths)->acquire_launch_lease(
            kA, "1.0.0", WaitPolicy::none());
        REQUIRE(running.held());
        CHECK_THROWS_AS(Installer(paths).purge(kA), BusyError);
        // Nothing written: no unfinished purge to block the very launch the
        // user is in the middle of, and nothing deleted.
        CHECK_FALSE(purge_pending(paths, kA));
        CHECK(TrustStore(paths).exists(kA));
        CHECK(Registry(paths).is_installed(kA));
    }
    CHECK_NOTHROW(Installer(paths).purge(kA));
}
#endif

TEST_CASE("CASE 5: purge never guesses ownership of the user's files") {
    test::TempLexeHome home;
    Work work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();
    install_with_state(paths, package_for(work.dir, key, kA), kA);

    // The user's own files, OUTSIDE .LEXE-managed storage, named after the
    // application as an export or a project folder would be. Placed in a
    // stand-in home folder inside the test root so nothing real is touched.
    const fs::path user = home.path() / "user-home";
    const fs::path exported = user / "Documents" / (std::string(kA) + "-export.txt");
    const fs::path project = user / "projects" / kA / "notes.txt";
    const fs::path named_in_record = user / (std::string(kA) + "-recorded.txt");
    util::spit(exported, std::string_view("export"));
    util::spit(project, std::string_view("notes"));
    util::spit(named_in_record, std::string_view("mine"));

    // And the installation record NAMING one of them as a file it created:
    // local, unsigned state is not a licence to delete a user's file.
    InstallationRecord rec = registry.read_record(kA);
    rec.created_files.push_back(named_in_record.string());
    registry.write_record(rec);

    Installer(paths).purge(kA);

    CHECK_FALSE(fs::exists(registry.app_data_dir(kA))); // .LEXE's storage: gone
    CHECK(util::slurp_text(exported) == "export");      // the user's: untouched
    CHECK(util::slurp_text(project) == "notes");
    CHECK(util::slurp_text(named_in_record) == "mine");
}

} // TEST_SUITE("purge")

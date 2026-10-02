// Regressions from the concurrency audit: three ways installed state could be
// left wrong by operations that each looked correct on their own.
//
// All three were found by mapping what the engine supervises and then checking
// whether every mutating path agreed with that map. None of them is a crash; two
// of them are asymmetries between operations that face the same hazard.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/paths.hpp"
#include "lexe/base/util.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/state/lock.hpp"
#include "lexe/state/registry.hpp"

#include <atomic>
#include <thread>
#include <algorithm>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

InstallOptions quiet_install() {
    InstallOptions opts;
    opts.explicit_trust = true;
    opts.desktop_integration = false;
    return opts;
}

} // namespace

TEST_SUITE("concurrent-state") {

// ------------------------------------------------------------------ atomicity

TEST_CASE("the installation record is written atomically") {
    // installation.json holds the current version, the pinned publisher key that
    // anchors update trust, and the update source. It used to be written with
    // truncate-then-write, and every launch rewrites it — while the launch lease
    // is SHARED on purpose, so concurrent launches are ordinary rather than
    // exotic.
    //
    // A torn read was never actually observed (24000 concurrent reads against 18
    // concurrent launches all parsed), because the document is well under a page.
    // So what this pins is the GUARANTEE, not a reproduced corruption: a reader
    // sees the whole old record or the whole new one.
    //
    // Checked by consequence, because "atomic" is not directly observable from
    // one thread: after a write, no temporary is left beside the record. A
    // rename-based write leaves none; a truncate-based write never made one.
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const Registry registry(paths);

    InstallationRecord record;
    record.id = "com.example.atomic";
    record.version = "1.0.0";
    record.publisher_key = "ed25519:" + std::string(43, 'A') + "=";
    record.source = "/tmp/whatever.lexe";
    registry.write_record(record);

    const fs::path dir = registry.app_dir(record.id);
    const InstallationRecord back = registry.read_record(record.id);
    CHECK(back.id == record.id);
    CHECK(back.version == "1.0.0");
    CHECK(back.publisher_key == record.publisher_key);

    // Rewriting repeatedly must not accumulate debris next to the record.
    for (int i = 0; i < 20; ++i) {
        record.version = "1.0." + std::to_string(i);
        registry.write_record(record);
    }
    std::vector<std::string> stray;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        const std::string name = entry.path().filename().string();
        if (name == "installation.json") continue;
        stray.push_back(name);
    }
    INFO("an atomic write must clean up after itself; leftovers here would be "
         "half-written records under names nothing reads");
    CHECK(stray.empty());
    CHECK(registry.read_record(record.id).version == "1.0.19");
}

TEST_CASE("concurrent atomic writes do not destroy each other") {
    // REGRESSION, and the defect was introduced by the fix for the case above.
    //
    // `write_atomic` used one temporary name for every writer: `<file>.tmp`. Two
    // processes writing the same file at once therefore collided -- the first
    // renamed the shared temporary into place, the second found its own
    // temporary gone and threw "cannot write file atomically".
    //
    // The throw was not the worst of it. On the way out, the loser removed the
    // DESTINATION before retrying, so it deleted the record the winner had just
    // written and only then reported failure. A function whose entire purpose is
    // that a reader sees the whole old content or the whole new content could
    // leave a reader seeing no file at all.
    //
    // Reproduced by the concurrency lane on `installation.json` during
    // simultaneous launches -- which is precisely the case that write was made
    // atomic for. The torn read it guarded against had never been observed once;
    // the collision it introduced happened two runs in five.
    //
    // Threads rather than processes here: the collision is over a shared PATH,
    // not over a file lock, so threads reproduce it and keep the test fast. The
    // cross-process form is covered by tests/concurrency/02_launch.sh.
    test::TempLexeHome home;
    const fs::path target = home.path() / "contended.json";

    constexpr int kWriters = 8;
    constexpr int kRounds = 40;
    std::atomic<int> failures{0};
    std::atomic<int> vanished{0};
    std::vector<std::thread> writers;
    writers.reserve(kWriters);

    for (int w = 0; w < kWriters; ++w) {
        writers.emplace_back([&, w] {
            for (int round = 0; round < kRounds; ++round) {
                const std::string payload =
                    "{\"writer\":" + std::to_string(w) + ",\"round\":" +
                    std::to_string(round) + "}";
                try {
                    util::write_atomic(target, std::string_view(payload));
                } catch (const std::exception&) {
                    ++failures;
                }
                // The file must NEVER be absent after it has been written once.
                // This is the assertion that would have caught the original
                // defect: the loser's cleanup removed a file it could not
                // replace, so a concurrent reader saw nothing there.
                std::error_code ec;
                if (!fs::exists(target, ec)) ++vanished;
            }
        });
    }
    for (std::thread& t : writers) t.join();

    INFO("write_atomic threw " << failures.load() << " time(s)");
    CHECK(failures.load() == 0);
    INFO("the destination was absent " << vanished.load()
                                       << " time(s) after being written");
    CHECK(vanished.load() == 0);

    // Whoever wrote last, the content must be ONE writer's payload in full --
    // never a mixture, which is what atomicity is for.
    const std::string final_text = util::slurp_text(target);
    INFO("final content: " << final_text);
    CHECK(final_text.front() == '{');
    CHECK(final_text.back() == '}');
    CHECK(std::count(final_text.begin(), final_text.end(), '{') == 1);

    // And no temporaries survive: a unique name per writer must still be
    // cleaned up, or the fix would trade a collision for unbounded litter.
    std::vector<std::string> stray;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(home.path(), ec)) {
        const std::string name = entry.path().filename().string();
        if (name != "contended.json") stray.push_back(name);
    }
    INFO("stray files: " << (stray.empty() ? std::string("none") : stray.front()));
    CHECK(stray.empty());
}

// ------------------------------------------------------------------ lock files

TEST_CASE("uninstall prunes version leases and keeps the mutation lock") {
    // REGRESSION, with a deliberate asymmetry that is the interesting half.
    //
    // `locks/` accumulated one `<id>.v.<version>.lease` for every version of every
    // application ever installed, and nothing deleted them — not even
    // `remove --purge-data`, the mode whose entire promise is that nothing is
    // left. Versions accumulate without limit, so that is the unbounded part.
    //
    // The per-app mutation lock is NOT deleted, and must not be. `flock` is
    // per-inode: unlinking a lock file does not release it, it makes the next
    // opener create a different inode and take a lock that excludes nobody. For
    // the lock that serialises install against uninstall, that is mutual exclusion
    // silently breaking — one process holding the old inode while another extracts
    // into the tree the first is deleting. One file per application is bounded, so
    // it stays.
    test::TempLexeHome home;
    const fs::path work = test::unique_temp_dir("lexe-lockclean-");
    const crypto::KeyPair key = crypto::generate_keypair();
    const Paths paths = Paths::detect();

    test::TestAppSpec spec;
    spec.id = "com.example.lockclean";
    spec.architectures = {host_architecture()};
    spec.version = "1.0.0";
    const fs::path v1 = test::make_test_package(work, key, spec);
    spec.version = "2.0.0";
    const fs::path v2 = test::make_test_package(work, key, spec);

    Installer installer(paths);
    installer.install(v1, quiet_install());
    installer.install(v2, quiet_install());

    const Registry registry(paths);
    // Touch the locks the way a launch and a mutation would, so there is
    // something to clean up.
    {
        const std::unique_ptr<OperationLockManager> locks =
            make_lock_manager(paths);
        const AppLock mutation =
            locks->lock_app_mutation(spec.id, "test", WaitPolicy::none());
    }
    // `const std::string&` over a brace list of `const char*` would bind to a
    // temporary on each iteration; name the type the list actually holds.
    for (const char* version : {"1.0.0", "2.0.0"}) {
        const std::unique_ptr<OperationLockManager> locks =
            make_lock_manager(paths);
        const LaunchLease lease =
            locks->acquire_launch_lease(spec.id, version, WaitPolicy::none());
    }
    CHECK(fs::exists(registry.mutation_lock_file(spec.id)));
    CHECK(fs::exists(registry.version_lease_file(spec.id, "1.0.0")));
    CHECK(fs::exists(registry.version_lease_file(spec.id, "2.0.0")));

    installer.purge(spec.id);

    INFO("the unbounded state must go");
    CHECK_FALSE(fs::exists(registry.version_lease_file(spec.id, "1.0.0")));
    CHECK_FALSE(fs::exists(registry.version_lease_file(spec.id, "2.0.0")));
    INFO("and the mutation lock must STAY: deleting it would break the mutual "
         "exclusion between a concurrent install and this uninstall");
    CHECK(fs::exists(registry.mutation_lock_file(spec.id)));

    fs::remove_all(work);
}

// ------------------------------------------------------------------ repair

TEST_CASE("repair refuses to rewrite a version that is in use") {
    // REGRESSION, and an asymmetry rather than a crash. `uninstall` and
    // `garbage_collect` both take an exclusive per-version lock before touching
    // files, precisely because mutating a live application's payload is unsafe.
    // Repair did not — and it restores files by overwriting them in place, same
    // inode, so an application that re-reads a data file or dlopen()s a library
    // saw it change underneath mid-session.
    //
    // The kernel already refuses the worst case (ETXTBSY on the running
    // entrypoint), which is why this went unnoticed: the dangerous case is every
    // OTHER file in the payload, which has no such protection.
    test::TempLexeHome home;
    const fs::path work = test::unique_temp_dir("lexe-repairlease-");
    const crypto::KeyPair key = crypto::generate_keypair();
    const Paths paths = Paths::detect();

    test::TestAppSpec spec;
    spec.id = "com.example.repairlease";
    spec.architectures = {host_architecture()};
    const fs::path pkg = test::make_test_package(work, key, spec);

    Installer installer(paths);
    installer.install(pkg, quiet_install());

    const Registry registry(paths);
    const std::string current = registry.current_version(spec.id);

    // Damage a payload file so repair has real work to do. Without this the
    // refusal would not be reached: repair only refuses when it would WRITE.
    const fs::path entry = registry.version_dir(spec.id, current) / spec.entrypoint;
    REQUIRE(fs::is_regular_file(entry));
    {
        std::string bytes = util::slurp_text(entry);
        bytes += "damage";
        util::spit(entry, bytes);
    }

    // Hold the version lease the way a running application does.
    const std::unique_ptr<OperationLockManager> locks = make_lock_manager(paths);
    const LaunchLease lease =
        locks->acquire_launch_lease(spec.id, current, WaitPolicy::none());

    CHECK_THROWS_AS(installer.repair(spec.id, std::nullopt, {}), BusyError);

    fs::remove_all(work);
}

TEST_CASE("repair proceeds once the version is no longer in use") {
    // The other half: the refusal must be about the lease, not about repair being
    // broken. A refusal that never lifts is a repair command nobody can run.
    test::TempLexeHome home;
    const fs::path work = test::unique_temp_dir("lexe-repairfree-");
    const crypto::KeyPair key = crypto::generate_keypair();
    const Paths paths = Paths::detect();

    test::TestAppSpec spec;
    spec.id = "com.example.repairfree";
    spec.architectures = {host_architecture()};
    const fs::path pkg = test::make_test_package(work, key, spec);

    Installer installer(paths);
    installer.install(pkg, quiet_install());

    const Registry registry(paths);
    const std::string current = registry.current_version(spec.id);
    const fs::path entry = registry.version_dir(spec.id, current) / spec.entrypoint;
    {
        std::string bytes = util::slurp_text(entry);
        bytes += "damage";
        util::spit(entry, bytes);
    }

    {
        // Held, then released by leaving the scope — the running application
        // exiting.
        const std::unique_ptr<OperationLockManager> locks =
            make_lock_manager(paths);
        const LaunchLease lease =
            locks->acquire_launch_lease(spec.id, current, WaitPolicy::none());
        CHECK_THROWS_AS(installer.repair(spec.id, std::nullopt, {}), BusyError);
    }

    const RepairReport report = installer.repair(spec.id, std::nullopt, {});
    CHECK(report.ok);
    CHECK(report.repaired_files.size() == 1);

    fs::remove_all(work);
}

TEST_CASE("an undamaged installation can be repaired while it runs") {
    // The refusal is placed where repair would WRITE, not at the top of the
    // function, on purpose: repair also re-resolves the runtime contract and
    // re-establishes desktop integration, and both are harmless while the
    // application runs. Refusing unconditionally would make repair unusable for
    // the case it is most often wanted in — an application that is running badly.
    test::TempLexeHome home;
    const fs::path work = test::unique_temp_dir("lexe-repairnoop-");
    const crypto::KeyPair key = crypto::generate_keypair();
    const Paths paths = Paths::detect();

    test::TestAppSpec spec;
    spec.id = "com.example.repairnoop";
    spec.architectures = {host_architecture()};
    const fs::path pkg = test::make_test_package(work, key, spec);

    Installer installer(paths);
    installer.install(pkg, quiet_install());

    const Registry registry(paths);
    const std::unique_ptr<OperationLockManager> locks = make_lock_manager(paths);
    const LaunchLease lease = locks->acquire_launch_lease(
        spec.id, registry.current_version(spec.id), WaitPolicy::none());

    const RepairReport report = installer.repair(spec.id, std::nullopt, {});
    CHECK(report.ok);
    CHECK(report.repaired_files.empty());

    fs::remove_all(work);
}

} // TEST_SUITE

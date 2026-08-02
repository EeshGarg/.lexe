// operation-lock tests (runtime-trust WS9). Three layers: the abstraction
// contract via the in-process fake (every platform), the real flock backend
// (POSIX), and proof the Installer actually consults the lock (injected fake).

#include <doctest/doctest.h>

#include "helpers.hpp"
#include "lock_fake.hpp"

#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/lock.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

constexpr const char* kAppA = "com.example.one";
constexpr const char* kAppB = "com.example.two";

fs::path make_pkg(const fs::path& work, const crypto::KeyPair& key,
                  const std::string& id) {
    test::TestAppSpec spec;
    spec.id = id;
    return test::make_test_package(work, key, spec);
}

} // namespace

TEST_SUITE("lock") {

// ------------------------------------------------ abstraction contract (fake)

TEST_CASE("fake: exclusive app mutation serializes same id, admits different id") {
    test::FakeLockManager m;

    AppLock a = m.lock_app_mutation(kAppA, "install", WaitPolicy::none());
    CHECK(a.held());
    CHECK(m.app_locked(kAppA));

    // Same id, second acquisition: busy.
    CHECK_THROWS_AS(m.lock_app_mutation(kAppA, "remove", WaitPolicy::none()),
                    BusyError);

    // Different id: concurrent.
    AppLock b = m.lock_app_mutation(kAppB, "install", WaitPolicy::none());
    CHECK(b.held());

    // Releasing frees the id for the next holder.
    a.release();
    CHECK_FALSE(m.app_locked(kAppA));
    AppLock a2 = m.lock_app_mutation(kAppA, "update", WaitPolicy::none());
    CHECK(a2.held());
}

TEST_CASE("fake: launch leases are shared; GC exclusivity is mutual") {
    test::FakeLockManager m;

    LaunchLease l1 = m.acquire_launch_lease(kAppA, "1.0.0", WaitPolicy::none());
    LaunchLease l2 = m.acquire_launch_lease(kAppA, "1.0.0", WaitPolicy::none());
    CHECK(l1.held());
    CHECK(l2.held());
    CHECK(m.lease_count(kAppA, "1.0.0") == 2);

    // GC cannot take the version while a lease is held.
    CHECK_FALSE(m.try_lock_version_for_gc(kAppA, "1.0.0").has_value());

    // Once every lease drops, GC may take it exclusively…
    l1.release();
    l2.release();
    std::optional<LaunchLease> gc = m.try_lock_version_for_gc(kAppA, "1.0.0");
    REQUIRE(gc.has_value());
    CHECK(gc->mode() == LockMode::Exclusive);

    // …and a new launch lease is refused while GC holds it.
    CHECK_THROWS_AS(m.acquire_launch_lease(kAppA, "1.0.0", WaitPolicy::none()),
                    BusyError);
}

TEST_CASE("fake: global recovery lock is exclusive") {
    test::FakeLockManager m;
    GlobalRecoveryLock g = m.lock_global_recovery(WaitPolicy::none());
    CHECK(g.held());
    CHECK_THROWS_AS(m.lock_global_recovery(WaitPolicy::none()), BusyError);
    g.release();
    CHECK_NOTHROW(m.lock_global_recovery(WaitPolicy::none()));
}

// -------------------------------------------------- real flock backend (POSIX)

#ifndef _WIN32
TEST_CASE("flock: same-id mutation excludes, different-id is concurrent") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    std::unique_ptr<OperationLockManager> m = make_lock_manager(paths);

    AppLock a = m->lock_app_mutation(kAppA, "install", WaitPolicy::none());
    CHECK(a.held());
    // A second open-file-description on the same lock file is a distinct flock
    // request even in-process: the kernel refuses it non-blocking.
    CHECK_THROWS_AS(m->lock_app_mutation(kAppA, "remove", WaitPolicy::none()),
                    BusyError);
    // Different app id → different lock file → granted.
    AppLock b = m->lock_app_mutation(kAppB, "install", WaitPolicy::none());
    CHECK(b.held());

    a.release();
    CHECK_NOTHROW(m->lock_app_mutation(kAppA, "update", WaitPolicy::none()));
}

TEST_CASE("flock: shared leases coexist and block version GC") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    std::unique_ptr<OperationLockManager> m = make_lock_manager(paths);

    LaunchLease l1 = m->acquire_launch_lease(kAppA, "1.0.0", WaitPolicy::none());
    LaunchLease l2 = m->acquire_launch_lease(kAppA, "1.0.0", WaitPolicy::none());
    CHECK(l1.held());
    CHECK(l2.held());
    // A runner holds the version, so GC must not be able to take it.
    CHECK_FALSE(m->try_lock_version_for_gc(kAppA, "1.0.0").has_value());

    l1.release();
    l2.release();
    // No lease held → GC takes it exclusively, and a new lease is then refused.
    std::optional<LaunchLease> gc = m->try_lock_version_for_gc(kAppA, "1.0.0");
    REQUIRE(gc.has_value());
    CHECK_THROWS_AS(m->acquire_launch_lease(kAppA, "1.0.0", WaitPolicy::none()),
                    BusyError);
}

TEST_CASE("flock: bounded wait yields BusyError when the holder does not release") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    std::unique_ptr<OperationLockManager> m = make_lock_manager(paths);

    AppLock a = m->lock_app_mutation(kAppA, "install", WaitPolicy::none());
    const auto t0 = std::chrono::steady_clock::now();
    CHECK_THROWS_AS(
        m->lock_app_mutation(kAppA, "remove",
                             WaitPolicy::bounded(std::chrono::milliseconds(60))),
        BusyError);
    const auto waited = std::chrono::steady_clock::now() - t0;
    // It actually waited roughly the bound before giving up (not instantly).
    CHECK(waited >= std::chrono::milliseconds(40));
}
#endif // _WIN32

// -------------------------------------- Installer consults the mutation lock

TEST_CASE("installer: a held app lock makes a same-id install busy") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();

    auto locks = std::make_shared<test::FakeLockManager>();

    // Something else is mutating kAppA (holds its lock).
    AppLock other = locks->lock_app_mutation(kAppA, "update", WaitPolicy::none());

    Installer installer(paths, locks);
    installer.set_mutation_wait(WaitPolicy::none());

    const fs::path pkg = make_pkg(work, key, kAppA);
    CHECK_THROWS_AS(installer.install(pkg), BusyError);

    // A DIFFERENT app id is unaffected — it installs concurrently.
    const fs::path pkg_b = make_pkg(work, key, kAppB);
    CHECK_NOTHROW(installer.install(pkg_b));

    // Once the other holder releases, the same-id install proceeds.
    other.release();
    CHECK_NOTHROW(installer.install(pkg));
}

TEST_CASE("installer: uninstall and rollback are gated by the app lock") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();

    auto locks = std::make_shared<test::FakeLockManager>();
    Installer installer(paths, locks);
    installer.set_mutation_wait(WaitPolicy::none());

    installer.install(make_pkg(work, key, kAppA)); // grants + releases

    // Now simulate a concurrent holder and confirm destructive ops refuse.
    AppLock other = locks->lock_app_mutation(kAppA, "recover", WaitPolicy::none());
    CHECK_THROWS_AS(installer.uninstall(kAppA), BusyError);
    CHECK_THROWS_AS(installer.rollback(kAppA), BusyError);
    CHECK_THROWS_AS(installer.repair(kAppA), BusyError);
}

TEST_CASE("installer: uninstall refuses while a version is leased (running)") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();

    auto locks = std::make_shared<test::FakeLockManager>();
    Installer installer(paths, locks);
    installer.set_mutation_wait(WaitPolicy::none());
    installer.install(make_pkg(work, key, kAppA));

    // A launch is running: it holds a SHARED lease on the active version.
    LaunchLease running =
        locks->acquire_launch_lease(kAppA, "1.0.0", WaitPolicy::none());

    // Uninstall must not delete files out from under it — it refuses (busy),
    // rather than silently killing the running app.
    CHECK_THROWS_AS(installer.uninstall(kAppA), BusyError);
    CHECK(Registry(paths).is_installed(kAppA)); // still fully installed

    // When the launch ends and the lease drops, uninstall succeeds.
    running.release();
    CHECK_NOTHROW(installer.uninstall(kAppA));
    CHECK_FALSE(Registry(paths).is_installed(kAppA));
}

} // TEST_SUITE("lock")

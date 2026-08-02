// Real cross-process race tests for the operation-lock backend (runtime-trust
// WS9). These fork actual child processes that acquire the REAL flock-backed
// locks, so they prove the properties that in-process tests cannot: mutual
// exclusion between separate processes, shared-lease coexistence, GC
// exclusivity, and — the property no timestamp heuristic can provide —
// AUTOMATIC RELEASE ON PROCESS DEATH (a killed holder's lock is immediately
// available to another process because the kernel drops it).
//
// POSIX only. On Windows this translation unit is empty (the single-writer
// backend has no cross-process semantics to exercise).

#ifndef _WIN32

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/lock.hpp"
#include "core/paths.hpp"

#include <csignal>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <sys/wait.h>
#include <unistd.h>

using namespace lexe;

namespace {

constexpr const char* kAppA = "com.example.one";
constexpr const char* kAppB = "com.example.two";
constexpr const char* kVer = "1.0.0";

// Child exit codes.
constexpr int kAcquired = 0; // took the lock/lease as expected
constexpr int kBusy = 6;     // BusyError trying to acquire
constexpr int kInUse = 5;    // try_lock_version_for_gc returned nullopt
constexpr int kError = 9;    // anything unexpected

enum class Hold { AppMutation, LeaseShared, GlobalRecovery, VersionGc };

void signal_ready(int fd) {
    const char c = 1;
    const ssize_t n = ::write(fd, &c, 1);
    (void)n;
}
[[noreturn]] void hold_until_killed() {
    for (;;) ::pause();
}

/// Fork a child that acquires `kind` and holds it until it is killed, writing
/// one byte to `ready_fd` the moment it holds the lock. Returns the child pid
/// to the parent; the child never returns.
pid_t spawn_holder(Hold kind, const std::string& id, const std::string& ver,
                   int ready_fd) {
    const pid_t pid = ::fork();
    if (pid != 0) return pid;

    // ---- child ----
    std::unique_ptr<OperationLockManager> m = make_lock_manager(Paths::detect());
    try {
        switch (kind) {
        case Hold::AppMutation: {
            AppLock l = m->lock_app_mutation(id, "hold", WaitPolicy::none());
            signal_ready(ready_fd);
            hold_until_killed();
        }
        case Hold::LeaseShared: {
            LaunchLease l = m->acquire_launch_lease(id, ver, WaitPolicy::none());
            signal_ready(ready_fd);
            hold_until_killed();
        }
        case Hold::GlobalRecovery: {
            GlobalRecoveryLock l = m->lock_global_recovery(WaitPolicy::none());
            signal_ready(ready_fd);
            hold_until_killed();
        }
        case Hold::VersionGc: {
            std::optional<LaunchLease> l = m->try_lock_version_for_gc(id, ver);
            if (!l.has_value()) ::_exit(kError);
            signal_ready(ready_fd);
            hold_until_killed();
        }
        }
    } catch (...) {
        ::_exit(kError);
    }
    ::_exit(kError);
}

/// Run `fn` in a forked child and return its exit code. `fn` returns the code.
int run_in_child(const std::function<int()>& fn) {
    const pid_t pid = ::fork();
    if (pid == 0) {
        int code = kError;
        try {
            code = fn();
        } catch (...) {
            code = kError;
        }
        ::_exit(code);
    }
    int status = 0;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

void kill_and_reap(pid_t pid) {
    ::kill(pid, SIGKILL);
    ::waitpid(pid, nullptr, 0);
}

/// A live holder process plus the pipe end that reports its readiness.
struct Holder {
    pid_t pid = -1;
    int read_fd = -1;
};

Holder start_holder(Hold kind, const std::string& id,
                    const std::string& ver = kVer) {
    int fds[2];
    REQUIRE(::pipe(fds) == 0);
    const pid_t pid = spawn_holder(kind, id, ver, fds[1]);
    ::close(fds[1]);          // parent keeps only the read end
    char c = 0;
    const ssize_t n = ::read(fds[0], &c, 1); // blocks until child holds the lock
    (void)n;
    return {pid, fds[0]};
}

// Contenders that a separate process runs to probe a lock.
int try_app_mutation(const std::string& id) {
    std::unique_ptr<OperationLockManager> m = make_lock_manager(Paths::detect());
    try {
        AppLock l = m->lock_app_mutation(id, "try", WaitPolicy::none());
        return kAcquired;
    } catch (const BusyError&) {
        return kBusy;
    } catch (...) {
        return kError;
    }
}
int try_launch_lease(const std::string& id) {
    std::unique_ptr<OperationLockManager> m = make_lock_manager(Paths::detect());
    try {
        LaunchLease l = m->acquire_launch_lease(id, kVer, WaitPolicy::none());
        return kAcquired;
    } catch (const BusyError&) {
        return kBusy;
    } catch (...) {
        return kError;
    }
}
int try_global_recovery() {
    std::unique_ptr<OperationLockManager> m = make_lock_manager(Paths::detect());
    try {
        GlobalRecoveryLock l = m->lock_global_recovery(WaitPolicy::none());
        return kAcquired;
    } catch (const BusyError&) {
        return kBusy;
    } catch (...) {
        return kError;
    }
}

} // namespace

TEST_SUITE("race") {

TEST_CASE("race: app mutation lock — exclusion, concurrency, death-release") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    std::unique_ptr<OperationLockManager> m = make_lock_manager(paths);

    // A separate process holds kAppA's mutation lock.
    Holder holder = start_holder(Hold::AppMutation, kAppA);

    // (1) Same id, this process: exclusion — busy.
    CHECK_THROWS_AS(m->lock_app_mutation(kAppA, "install", WaitPolicy::none()),
                    BusyError);
    // (2) A THIRD process also sees the same id as busy.
    CHECK(run_in_child([&] { return try_app_mutation(kAppA); }) == kBusy);
    // (3) A different id is unaffected — granted concurrently.
    {
        AppLock other = m->lock_app_mutation(kAppB, "install", WaitPolicy::none());
        CHECK(other.held());
    }

    // (4) The holder dies WITHOUT releasing. The kernel drops its flock, so the
    // lock becomes available to us immediately — no timestamp, no reaping of a
    // stale file. This is the property the whole design rests on.
    kill_and_reap(holder.pid);
    CHECK_NOTHROW(m->lock_app_mutation(kAppA, "install", WaitPolicy::none()));
    ::close(holder.read_fd);
}

TEST_CASE("race: launch leases — shared coexistence, GC block, death-release") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    std::unique_ptr<OperationLockManager> m = make_lock_manager(paths);

    // Another process is running kAppA @ kVer: it holds a SHARED lease.
    Holder holder = start_holder(Hold::LeaseShared, kAppA, kVer);

    // (5) A second shared lease from THIS process coexists with it.
    std::optional<LaunchLease> mine =
        std::make_optional(m->acquire_launch_lease(kAppA, kVer, WaitPolicy::none()));
    CHECK(mine->held());

    // (6) GC cannot take the version while any lease is held.
    CHECK_FALSE(m->try_lock_version_for_gc(kAppA, kVer).has_value());

    // Drop our lease; the holder still has one, so GC still cannot take it.
    mine.reset();
    CHECK_FALSE(m->try_lock_version_for_gc(kAppA, kVer).has_value());

    // (7) The running process dies: its lease is released by the kernel and GC
    // may now reclaim the version.
    kill_and_reap(holder.pid);
    CHECK(m->try_lock_version_for_gc(kAppA, kVer).has_value());
    ::close(holder.read_fd);
}

TEST_CASE("race: GC exclusivity blocks launches, released on death") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    std::unique_ptr<OperationLockManager> m = make_lock_manager(paths);

    // A GC/uninstall in another process holds the version EXCLUSIVELY.
    Holder holder = start_holder(Hold::VersionGc, kAppA, kVer);

    // (8) A launch cannot lease the version while it is held exclusively.
    CHECK_THROWS_AS(m->acquire_launch_lease(kAppA, kVer, WaitPolicy::none()),
                    BusyError);
    CHECK(run_in_child([&] { return try_launch_lease(kAppA); }) == kBusy);

    // The exclusive holder dies → the version is launchable again.
    kill_and_reap(holder.pid);
    CHECK_NOTHROW(m->acquire_launch_lease(kAppA, kVer, WaitPolicy::none()));
    ::close(holder.read_fd);
}

TEST_CASE("race: global recovery lock — exclusion + death-release") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    std::unique_ptr<OperationLockManager> m = make_lock_manager(paths);

    // Another process is running a recovery pass (holds the global lock).
    Holder holder = start_holder(Hold::GlobalRecovery, "");

    // (9) Recovery is globally serialized: we cannot take it, nor can a third.
    CHECK_THROWS_AS(m->lock_global_recovery(WaitPolicy::none()), BusyError);
    CHECK(run_in_child([&] { return try_global_recovery(); }) == kBusy);

    // (10) The recovering process dies → the global lock frees immediately.
    kill_and_reap(holder.pid);
    CHECK_NOTHROW(m->lock_global_recovery(WaitPolicy::none()));
    ::close(holder.read_fd);

    (void)kInUse; // documented exit code, not needed by these cases
}

} // TEST_SUITE("race")

#endif // _WIN32

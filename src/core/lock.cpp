// Operation locking (runtime-trust WS9). POSIX backend uses flock(2); the
// non-POSIX backend is a permissive single-writer stand-in. See lock.hpp for
// the design contract (kernel-released locks, no timestamp staleness, no
// check-then-create).

#include "core/lock.hpp"

#include "core/error.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <cassert>
#include <chrono>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#else
#include <process.h>
#endif

namespace lexe {
namespace fs = std::filesystem;

const char* to_string(LockClass c) noexcept {
    switch (c) {
    case LockClass::GlobalRecovery: return "global-recovery";
    case LockClass::AppMutation:    return "app-mutation";
    case LockClass::VersionLease:   return "version-lease";
    case LockClass::Registry:       return "registry";
    }
    return "?";
}

std::string LockOwner::to_line() const {
    std::ostringstream os;
    os << "pid=" << pid << " start=" << start_token << " op=" << operation
       << " at=" << acquired_at << "\n";
    return os.str();
}

namespace {

// --- per-thread lock-order verification (deadlock-avoidance tripwire) ---
// The classes this thread currently holds. Acquiring class X asserts that no
// strictly-greater class is already held (acquire order is low → high). Our
// code upholds the order by construction; the assert catches regressions.
thread_local std::vector<int> g_held_classes;

void order_register(LockClass c) {
    const int cls = static_cast<int>(c);
    for (const int held : g_held_classes) {
        assert(held <= cls &&
               "lock-order violation: acquiring an earlier class while holding "
               "a later one (see docs/CONCURRENCY.md)");
        (void)held;
    }
    g_held_classes.push_back(cls);
}

void order_unregister(LockClass c) {
    const int cls = static_cast<int>(c);
    for (auto it = g_held_classes.rbegin(); it != g_held_classes.rend(); ++it) {
        if (*it == cls) {
            g_held_classes.erase(std::next(it).base());
            return;
        }
    }
}

/// Base held-lock: tracks lock-order registration so every backend gets the
/// deadlock tripwire. Registration happens at construction (post-acquire) and
/// is undone exactly once on release/destruction.
class TrackedHandle : public LockHandle {
public:
    explicit TrackedHandle(LockClass cls) : cls_(cls) { order_register(cls_); }
    ~TrackedHandle() override { unregister_once(); }

protected:
    void unregister_once() {
        if (registered_) {
            order_unregister(cls_);
            registered_ = false;
        }
    }
    LockClass cls_;
    bool registered_ = true;
};

#ifndef _WIN32

/// This process's start token: /proc/self/stat field 22 (starttime, in clock
/// ticks since boot). Stable for the process's lifetime, so pid + start token
/// uniquely identifies a live process across PID reuse. Diagnostics only.
std::string proc_start_token() {
    try {
        const std::string stat = util::slurp_text("/proc/self/stat");
        // Field 2 is "(comm)" and may itself contain spaces/parens, so skip to
        // the last ')' and count fields from there (field 3 onward).
        const std::size_t rp = stat.rfind(')');
        if (rp != std::string::npos && rp + 1 < stat.size()) {
            std::istringstream is(stat.substr(rp + 1));
            std::string tok;
            int field = 2; // the token AFTER ')' is field 3
            while (is >> tok) {
                ++field;
                if (field == 22) return tok;
            }
        }
    } catch (...) {
    }
    return "unknown";
}

/// Open (creating if needed) a lock file for OS-level locking. O_CLOEXEC keeps
/// the descriptor out of any child we later exec (a sandboxed app must never
/// inherit — or be able to observe — our lock fds).
int open_lock_file(const fs::path& file) {
    std::error_code ec;
    fs::create_directories(file.parent_path(), ec);
    const int fd = ::open(file.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        throw LockError("lock: cannot open " + file.string() + ": " +
                        std::strerror(errno));
    }
    return fd;
}

/// Take the flock on `fd`. Returns true on success, false when the lock is held
/// by someone else and the wait bound elapsed (caller maps to BusyError).
/// Throws LockError on a genuine system failure.
bool flock_acquire(int fd, LockMode mode, const WaitPolicy& wait,
                   const fs::path& file) {
    const int base = (mode == LockMode::Exclusive) ? LOCK_EX : LOCK_SH;
    if (wait.block_forever) {
        while (::flock(fd, base) != 0) {
            if (errno == EINTR) continue;
            throw LockError("lock: flock(" + file.string() +
                            "): " + std::strerror(errno));
        }
        return true;
    }
    const auto deadline = std::chrono::steady_clock::now() + wait.timeout;
    for (;;) {
        if (::flock(fd, base | LOCK_NB) == 0) return true;
        if (errno == EINTR) continue;
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            throw LockError("lock: flock(" + file.string() +
                            "): " + std::strerror(errno));
        }
        if (wait.timeout.count() <= 0 ||
            std::chrono::steady_clock::now() >= deadline) {
            return false; // held by another; bound elapsed
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

class FlockHandle : public TrackedHandle {
public:
    FlockHandle(int fd, LockClass cls) : TrackedHandle(cls), fd_(fd) {}
    ~FlockHandle() override { release(); }

    void release() override {
        if (fd_ >= 0) {
            // Closing the fd drops the flock; the kernel does the same on death.
            ::flock(fd_, LOCK_UN);
            ::close(fd_);
            fd_ = -1;
        }
        unregister_once();
    }
    bool held() const override { return fd_ >= 0; }

private:
    int fd_;
};

/// Best-effort: record the owner line in the (exclusively held) lock file for
/// diagnostics. Never fails the acquisition — the lock is what matters.
void write_owner_record(int fd, const LockOwner& owner) {
    const std::string line = owner.to_line();
    if (::ftruncate(fd, 0) != 0) return;
    (void)::pwrite(fd, line.data(), line.size(), 0);
}

class FlockLockManager : public OperationLockManager {
public:
    explicit FlockLockManager(Paths paths)
        : paths_(std::move(paths)), registry_(paths_) {}

    AppLock lock_app_mutation(const std::string& id, const std::string& op,
                              const WaitPolicy& wait) override {
        const fs::path file = registry_.mutation_lock_file(id); // validates id
        const int fd = open_lock_file(file);
        if (!flock_acquire(fd, LockMode::Exclusive, wait, file)) {
            ::close(fd);
            throw BusyError("application " + id +
                            " is busy: another operation (" + op +
                            ") holds its mutation lock");
        }
        write_owner_record(fd, self_owner(op));
        return AppLock(std::make_unique<FlockHandle>(fd, LockClass::AppMutation),
                       id, op);
    }

    LaunchLease acquire_launch_lease(const std::string& id,
                                     const std::string& version,
                                     const WaitPolicy& wait) override {
        const fs::path file = registry_.version_lease_file(id, version);
        const int fd = open_lock_file(file);
        if (!flock_acquire(fd, LockMode::Shared, wait, file)) {
            ::close(fd);
            throw BusyError("cannot lease " + id + " " + version +
                            ": a version-exclusive operation is in progress");
        }
        return LaunchLease(
            std::make_unique<FlockHandle>(fd, LockClass::VersionLease), id,
            version, LockMode::Shared);
    }

    std::optional<LaunchLease> try_lock_version_for_gc(
        const std::string& id, const std::string& version) override {
        const fs::path file = registry_.version_lease_file(id, version);
        const int fd = open_lock_file(file);
        // Non-blocking exclusive: success means NO launch lease is held.
        if (!flock_acquire(fd, LockMode::Exclusive, WaitPolicy::none(), file)) {
            ::close(fd);
            return std::nullopt; // a runner holds the version; do not touch it
        }
        return LaunchLease(
            std::make_unique<FlockHandle>(fd, LockClass::VersionLease), id,
            version, LockMode::Exclusive);
    }

    GlobalRecoveryLock lock_global_recovery(const WaitPolicy& wait) override {
        const fs::path file = registry_.global_recovery_lock_file();
        const int fd = open_lock_file(file);
        if (!flock_acquire(fd, LockMode::Exclusive, wait, file)) {
            ::close(fd);
            throw BusyError("global recovery is already in progress");
        }
        write_owner_record(fd, self_owner("recover"));
        return GlobalRecoveryLock(
            std::make_unique<FlockHandle>(fd, LockClass::GlobalRecovery));
    }

    LockOwner self_owner(const std::string& operation) const override {
        LockOwner o;
        o.pid = static_cast<long>(::getpid());
        o.start_token = proc_start_token();
        o.operation = operation;
        o.acquired_at = util::now_utc_string();
        return o;
    }

private:
    Paths paths_;
    Registry registry_;
};

#else // _WIN32

/// Permissive single-writer handle: no OS lock (the Windows dev host is a
/// single user with no isolation backend), only lock-order tracking.
class NullHandle : public TrackedHandle {
public:
    explicit NullHandle(LockClass cls) : TrackedHandle(cls) {}
    ~NullHandle() override { unregister_once(); }
    void release() override { unregister_once(); }
    bool held() const override { return registered_; }
};

class NullLockManager : public OperationLockManager {
public:
    explicit NullLockManager(Paths paths) : paths_(std::move(paths)) {}

    AppLock lock_app_mutation(const std::string& id, const std::string& op,
                              const WaitPolicy&) override {
        return AppLock(std::make_unique<NullHandle>(LockClass::AppMutation), id,
                       op);
    }
    LaunchLease acquire_launch_lease(const std::string& id,
                                     const std::string& version,
                                     const WaitPolicy&) override {
        return LaunchLease(std::make_unique<NullHandle>(LockClass::VersionLease),
                           id, version, LockMode::Shared);
    }
    std::optional<LaunchLease> try_lock_version_for_gc(
        const std::string& id, const std::string& version) override {
        return LaunchLease(std::make_unique<NullHandle>(LockClass::VersionLease),
                           id, version, LockMode::Exclusive);
    }
    GlobalRecoveryLock lock_global_recovery(const WaitPolicy&) override {
        return GlobalRecoveryLock(
            std::make_unique<NullHandle>(LockClass::GlobalRecovery));
    }
    LockOwner self_owner(const std::string& operation) const override {
        LockOwner o;
        o.pid = static_cast<long>(::_getpid());
        o.start_token = "win";
        o.operation = operation;
        o.acquired_at = util::now_utc_string();
        return o;
    }

private:
    Paths paths_;
};

#endif

} // namespace

std::unique_ptr<OperationLockManager> make_lock_manager(const Paths& paths) {
#ifndef _WIN32
    return std::make_unique<FlockLockManager>(paths);
#else
    return std::make_unique<NullLockManager>(paths);
#endif
}

} // namespace lexe

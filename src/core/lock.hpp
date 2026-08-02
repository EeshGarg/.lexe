#pragma once
// Operation locking (runtime-trust WS9): a platform-neutral abstraction over
// OS-backed advisory locks that serialize destructive per-app operations,
// admit concurrent read/launch access, and coordinate global recovery —
// WITHOUT relying on lock-file timestamps or check-then-create races.
//
// Correctness rests on the kernel releasing the lock when the holder dies:
// flock(2) locks vanish on process exit or crash, so a lock file left on disk
// is NEVER by itself proof that anyone holds it, and a stale file is never
// deleted on a timestamp heuristic. Acquisition is atomic in the kernel.
//
// Ownership records (pid + start token) are written for diagnostics ONLY and
// are never consulted to decide liveness — the kernel decides that. pid plus a
// per-process start token defeats PID reuse: a recycled pid carrying a
// different start token is a different process.

#include "core/paths.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>

namespace lexe {

/// Exclusive (mutate) vs shared (read / launch-lease) access.
enum class LockMode { Exclusive, Shared };

/// The ordered lock classes. To preclude deadlock, a thread acquires locks in
/// increasing class order (GlobalRecovery first, Registry last) and never
/// blocks to take an EARLIER class while holding a LATER one. Enforced by a
/// per-thread assertion in debug builds; documented in docs/CONCURRENCY.md.
enum class LockClass {
    GlobalRecovery = 0, // coordinates recovery across all applications
    AppMutation    = 1, // per-app exclusive mutation (install/update/…)
    VersionLease   = 2, // per-(app,version) launch lease
    Registry       = 3, // short registry-record critical sections
};

const char* to_string(LockClass c) noexcept;

/// Identity of a lock holder, recorded in the lock file for diagnostics only.
/// NEVER used to decide whether the holder is alive.
struct LockOwner {
    long pid = 0;
    std::string start_token; // opaque, stable for the process's lifetime
    std::string operation;   // e.g. "install", "run", "recover"
    std::string acquired_at; // RFC 3339 UTC, diagnostics only

    std::string to_line() const; // single-line record written into lock files
};

/// How long an acquisition may wait for a conflicting holder.
struct WaitPolicy {
    std::chrono::milliseconds timeout{0};
    bool block_forever = false;

    /// Fail immediately (BusyError) if the lock is held.
    static WaitPolicy none() { return {std::chrono::milliseconds{0}, false}; }
    /// Wait up to `t`, then BusyError.
    static WaitPolicy bounded(std::chrono::milliseconds t) {
        return {t, false};
    }
    /// Block until the lock is free (used only where progress is guaranteed).
    static WaitPolicy forever() {
        return {std::chrono::milliseconds{0}, true};
    }
};

/// A backend-produced held lock. Releasing it (via a scoped wrapper's release()
/// or destructor) drops the OS-level lock. Backends implement this; callers use
/// the scoped types below rather than touching it directly.
class LockHandle {
public:
    virtual ~LockHandle() = default;
    virtual void release() = 0; // idempotent
    virtual bool held() const = 0;
};

// --- Scoped, move-only lock wrappers. Distinct types make lock discipline a
// compile-time property: a launch lease can never be passed where an exclusive
// mutation lock is required. ---

/// The per-app EXCLUSIVE mutation lock. Held for the duration of an
/// install/update/rollback/remove/recover/cleanup on one App ID.
class AppLock {
public:
    AppLock() = default;
    AppLock(std::unique_ptr<LockHandle> handle, std::string id, std::string op)
        : handle_(std::move(handle)), id_(std::move(id)), op_(std::move(op)) {}
    AppLock(AppLock&&) noexcept = default;
    AppLock& operator=(AppLock&&) noexcept = default;
    AppLock(const AppLock&) = delete;
    AppLock& operator=(const AppLock&) = delete;

    bool held() const { return handle_ && handle_->held(); }
    void release() {
        if (handle_) handle_->release();
    }
    const std::string& app_id() const { return id_; }
    const std::string& operation() const { return op_; }

private:
    std::unique_ptr<LockHandle> handle_;
    std::string id_;
    std::string op_;
};

/// A launch lease on (App ID, version). Shared among concurrent launches of the
/// same version; when taken exclusively (GC) it proves no launch is using the
/// version. Held for the run's duration by the launching process.
class LaunchLease {
public:
    LaunchLease() = default;
    LaunchLease(std::unique_ptr<LockHandle> handle, std::string id,
                std::string version, LockMode mode)
        : handle_(std::move(handle)),
          id_(std::move(id)),
          version_(std::move(version)),
          mode_(mode) {}
    LaunchLease(LaunchLease&&) noexcept = default;
    LaunchLease& operator=(LaunchLease&&) noexcept = default;
    LaunchLease(const LaunchLease&) = delete;
    LaunchLease& operator=(const LaunchLease&) = delete;

    bool held() const { return handle_ && handle_->held(); }
    void release() {
        if (handle_) handle_->release();
    }
    const std::string& app_id() const { return id_; }
    const std::string& version() const { return version_; }
    LockMode mode() const { return mode_; }

private:
    std::unique_ptr<LockHandle> handle_;
    std::string id_;
    std::string version_;
    LockMode mode_ = LockMode::Shared;
};

/// The global recovery lock. Serializes recovery passes with one another;
/// per-app mutations still take their own AppLock underneath it.
class GlobalRecoveryLock {
public:
    GlobalRecoveryLock() = default;
    explicit GlobalRecoveryLock(std::unique_ptr<LockHandle> handle)
        : handle_(std::move(handle)) {}
    GlobalRecoveryLock(GlobalRecoveryLock&&) noexcept = default;
    GlobalRecoveryLock& operator=(GlobalRecoveryLock&&) noexcept = default;
    GlobalRecoveryLock(const GlobalRecoveryLock&) = delete;
    GlobalRecoveryLock& operator=(const GlobalRecoveryLock&) = delete;

    bool held() const { return handle_ && handle_->held(); }
    void release() {
        if (handle_) handle_->release();
    }

private:
    std::unique_ptr<LockHandle> handle_;
};

/// Grants OS-backed locks. The Linux backend uses flock(2); the non-POSIX
/// backend is a permissive single-writer stand-in (keeps the dev host building
/// and running); tests use an in-process fake modelling the same contention.
class OperationLockManager {
public:
    virtual ~OperationLockManager() = default;

    /// Take the per-app EXCLUSIVE mutation lock. Waits per `wait`; throws
    /// BusyError when it cannot be taken within the bound (or immediately for
    /// WaitPolicy::none()); LockError on a system failure.
    virtual AppLock lock_app_mutation(const std::string& id,
                                      const std::string& operation,
                                      const WaitPolicy& wait) = 0;

    /// Take a SHARED launch lease on (id, version), held for the run's
    /// duration. Blocks only against an exclusive holder (a mutation-time GC or
    /// version-exclusive hold), per `wait`.
    virtual LaunchLease acquire_launch_lease(const std::string& id,
                                             const std::string& version,
                                             const WaitPolicy& wait) = 0;

    /// Non-blocking EXCLUSIVE hold of the (id, version) lease, for GC. Returns
    /// nullopt when any launch lease is held (the version is in use). Never
    /// blocks and never waits.
    virtual std::optional<LaunchLease> try_lock_version_for_gc(
        const std::string& id, const std::string& version) = 0;

    /// Take the GLOBAL recovery lock (exclusive), per `wait`.
    virtual GlobalRecoveryLock lock_global_recovery(const WaitPolicy& wait) = 0;

    /// This process's stable identity (pid + start token) for owner records.
    virtual LockOwner self_owner(const std::string& operation) const = 0;
};

/// The lock manager for `paths`: the flock backend on POSIX, else a permissive
/// single-writer backend. Creates the locks directory on first use.
std::unique_ptr<OperationLockManager> make_lock_manager(const Paths& paths);

} // namespace lexe

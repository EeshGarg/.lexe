#pragma once
// In-process fake OperationLockManager (runtime-trust WS9 test seam). Models
// the SAME contention semantics as the flock backend without touching the OS,
// so lock-dependent behavior can be exercised deterministically and on every
// platform. Single-threaded: a conflicting acquisition reports BusyError
// immediately rather than waiting (no real holder can release mid-call).

#include "core/error.hpp"
#include "core/lock.hpp"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace lexe::test {

/// A LockHandle that runs a release callback exactly once.
class FakeHandle : public LockHandle {
public:
    explicit FakeHandle(std::function<void()> on_release)
        : on_release_(std::move(on_release)) {}
    ~FakeHandle() override { release(); }
    void release() override {
        if (!released_) {
            released_ = true;
            if (on_release_) on_release_();
        }
    }
    bool held() const override { return !released_; }

private:
    std::function<void()> on_release_;
    bool released_ = false;
};

class FakeLockManager : public OperationLockManager {
public:
    // --- introspection for tests ---
    bool app_locked(const std::string& id) const {
        const auto it = app_excl_.find(id);
        return it != app_excl_.end() && it->second;
    }
    int lease_count(const std::string& id, const std::string& v) const {
        const auto it = lease_shared_.find(key(id, v));
        return it == lease_shared_.end() ? 0 : it->second;
    }

    AppLock lock_app_mutation(const std::string& id, const std::string& op,
                              const WaitPolicy& wait) override {
        if (app_excl_[id]) deny(wait, "application " + id + " is busy");
        app_excl_[id] = true;
        return AppLock(std::make_unique<FakeHandle>(
                           [this, id]() { app_excl_[id] = false; }),
                       id, op);
    }

    LaunchLease acquire_launch_lease(const std::string& id,
                                     const std::string& version,
                                     const WaitPolicy& wait) override {
        const std::string k = key(id, version);
        if (lease_excl_[k])
            deny(wait, "version-exclusive operation in progress: " + id);
        ++lease_shared_[k];
        return LaunchLease(std::make_unique<FakeHandle>(
                               [this, k]() { --lease_shared_[k]; }),
                           id, version, LockMode::Shared);
    }

    std::optional<LaunchLease> try_lock_version_for_gc(
        const std::string& id, const std::string& version) override {
        const std::string k = key(id, version);
        if (lease_shared_[k] > 0 || lease_excl_[k]) return std::nullopt;
        lease_excl_[k] = true;
        return LaunchLease(std::make_unique<FakeHandle>(
                               [this, k]() { lease_excl_[k] = false; }),
                           id, version, LockMode::Exclusive);
    }

    GlobalRecoveryLock lock_global_recovery(const WaitPolicy& wait) override {
        if (global_) deny(wait, "global recovery already in progress");
        global_ = true;
        return GlobalRecoveryLock(
            std::make_unique<FakeHandle>([this]() { global_ = false; }));
    }

    LockOwner self_owner(const std::string& operation) const override {
        LockOwner o;
        o.pid = 1;
        o.start_token = "fake";
        o.operation = operation;
        o.acquired_at = "1970-01-01T00:00:00Z";
        return o;
    }

private:
    static std::string key(const std::string& id, const std::string& v) {
        return id + "\n" + v;
    }
    static void deny(const WaitPolicy& wait, const std::string& msg) {
        (void)wait; // the fake never actually waits
        throw BusyError(msg);
    }

    std::map<std::string, bool> app_excl_;
    std::map<std::string, int> lease_shared_;
    std::map<std::string, bool> lease_excl_;
    bool global_ = false;
};

} // namespace lexe::test

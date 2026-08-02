#pragma once
// error — exception hierarchy and CLI exit-code mapping (ARCHITECTURE.md
// #Conventions). Exit codes: 0 ok, 1 runtime error, 2 usage, 3 verification
// failure, 4 not installed/found, 5 permission/consent required,
// 6 busy / operation conflict.

#include <stdexcept>
#include <string>

namespace lexe {

/// Base runtime error. CLI exit code 1.
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

/// Package/update verification failure (FORMAT-0.1 §6). CLI exit code 3.
class VerificationError : public Error {
public:
    using Error::Error;
};

/// Application/file/entry not installed or not found. CLI exit code 4.
class NotFoundError : public Error {
public:
    using Error::Error;
};

/// Bad command-line invocation. CLI exit code 2.
class UsageError : public Error {
public:
    using Error::Error;
};

/// An operation requires permission/consent that was not granted — e.g. an
/// update that expands the approved permission set (runtime-trust WS5). CLI
/// exit code 5. Distinct from a verification failure: the package is valid, the
/// user simply has not authorized the new capability.
class PermissionError : public Error {
public:
    using Error::Error;
};

/// A launch precondition failed — entrypoint containment, integrity, or
/// isolation-policy construction (runtime-trust WS6/WS7). The application is
/// NOT executed. Exit code 1 (a distinct type for programmatic handling; the
/// launch never falls through to direct execution).
class LaunchError : public Error {
public:
    using Error::Error;
};

/// A runtime-isolation policy could not be enforced (runtime-trust WS7): the
/// backend is unavailable, a required control (e.g. network denial) cannot be
/// established, or backend setup failed. The application is NOT executed and
/// the launch NEVER falls through to direct execution. A LaunchError, so the
/// launcher's fail-closed guarantee covers it.
class IsolationError : public LaunchError {
public:
    using LaunchError::LaunchError;
};

/// An App ID is busy: another exclusive mutation (install/update/rollback/
/// remove/recovery) holds the per-app lock, or a launch lease blocks a
/// destructive operation (runtime-trust WS9). CLI exit code 6.
class BusyError : public Error {
public:
    using Error::Error;
};

/// Persistent data is retained for an App ID under a DIFFERENT publisher key,
/// so a reinstall/install must not inherit it (runtime-trust WS8). The user
/// must purge the retained data first. CLI exit code 6.
class RetainedDataConflict : public Error {
public:
    using Error::Error;
};

/// A lock-system failure (runtime-trust WS9): a lock file could not be opened,
/// an OS lock/stat call failed, or recorded lock metadata is corrupt. Distinct
/// from BusyError — that is a healthy lock simply held by someone else, whereas
/// this is the locking machinery itself failing. CLI exit code 1 (the caller
/// fails closed rather than proceeding without the lock).
class LockError : public Error {
public:
    using Error::Error;
};

/// Map an exception to the CLI exit code documented above.
inline int exit_code_for(const std::exception& e) noexcept {
    if (dynamic_cast<const UsageError*>(&e) != nullptr) return 2;
    if (dynamic_cast<const VerificationError*>(&e) != nullptr) return 3;
    if (dynamic_cast<const NotFoundError*>(&e) != nullptr) return 4;
    if (dynamic_cast<const PermissionError*>(&e) != nullptr) return 5;
    if (dynamic_cast<const BusyError*>(&e) != nullptr) return 6;
    if (dynamic_cast<const RetainedDataConflict*>(&e) != nullptr) return 6;
    return 1;
}

} // namespace lexe

#pragma once
// error — exception hierarchy and CLI exit-code mapping (ARCHITECTURE.md
// #Conventions). Exit codes: 0 ok, 1 runtime error, 2 usage, 3 verification
// failure, 4 not installed/found.

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

/// Map an exception to the CLI exit code documented above.
inline int exit_code_for(const std::exception& e) noexcept {
    if (dynamic_cast<const UsageError*>(&e) != nullptr) return 2;
    if (dynamic_cast<const VerificationError*>(&e) != nullptr) return 3;
    if (dynamic_cast<const NotFoundError*>(&e) != nullptr) return 4;
    return 1;
}

} // namespace lexe

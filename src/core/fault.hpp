// fault — deterministic failpoints for crash-recovery testing (HARDENING.md
// §C). maybe("<site>") throws fault::Injected when the LEXE_TEST_FAULT
// environment variable equals "<site>", simulating a process that dies at a
// precise point in the install transaction. It is a cheap environment lookup
// compiled into all builds; only the test suite ever sets the variable, so
// production behaviour is unaffected.
//
// A fault is distinguishable from a genuine error so the installer can leave
// the journal mid-transaction (as a real crash would) instead of running its
// own in-process recovery — recovery is then exercised on the "next run" via
// Installer::recover_all().

#pragma once

#include "core/error.hpp"

#include <string>

namespace lexe::fault {

/// Thrown by maybe() when the active failpoint matches.
struct Injected : Error {
    explicit Injected(const std::string& site)
        : Error("fault injected at failpoint \"" + site + "\"") {}
};

/// Throw Injected if LEXE_TEST_FAULT == site; otherwise do nothing.
void maybe(const char* site);

} // namespace lexe::fault

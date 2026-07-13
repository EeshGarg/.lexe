#pragma once
// launcher — `lexe run <id>` (SPEC "Installed Application Representation").
// Resolves the current version, validates the entrypoint (must exist inside
// the current version dir — security invariant #6 — and be executable on
// POSIX), spawns it with cwd = version dir (argv array, no shell), waits,
// records last-run time and exit code in installation.json, and propagates
// the child's exit code.

#include "core/paths.hpp"

#include <string>
#include <vector>

namespace lexe {

/// Run the installed application `id`, appending `args` after the manifest's
/// `entrypoint.arguments`. Returns the child's exit code. Throws
/// NotFoundError when the app is not installed, Error when the entrypoint is
/// missing/unlaunchable.
int run_app(const Paths& paths, const std::string& id,
            const std::vector<std::string>& args);

} // namespace lexe

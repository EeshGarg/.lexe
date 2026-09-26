#pragma once
// launcher — `lexe run <id>`: the POST-INSTALL / RUN role of the Definitive
// Architecture (§7 definitive install+run flow, §15 durable launch, §16 runtime
// semantics).
//
//     run.lexe / menu entry
//        |
//        v  resolve installed app ID
//        v  verify state + execution policy      (§6 strict vs §8 normal)
//        v  resolve dependencies/runtime         (recorded at install, §16)
//        v  select execution chain               (§8)
//        v  SANDBOX / PREPARE                    (isolation.hpp)
//        v  exec internal application            (never a user-visible ELF)
//        v  record execution report              (§9)
//
// Two properties matter architecturally:
//
//   * Presentation is DECLARED, not inferred. A console application launched
//     with no terminal is given one (or has its output captured and recorded);
//     a GUI application opens directly; exit code 0 is SUCCESS even when no
//     window appears. The alpha's "console Hello World looked like a failed
//     launch" is a presentation bug, and this is where it is fixed (§14.4).
//
//   * Every launch produces an execution report, and every FAILED launch also
//     produces a structured error record, so a real failure is always
//     distinguishable from successful-but-invisible execution (§9).

#include "lexe/diagnostics/diagnostics.hpp"
#include "lexe/runtime/execpolicy.hpp"
#include "lexe/base/paths.hpp"

#include <optional>
#include <string>
#include <vector>

namespace lexe {

/// How the caller wants the launch presented and resolved.
struct RunRequest {
    std::string id;
    std::vector<std::string> args;
    /// Power-user override: force a specific execution chain id. It is still
    /// filtered through the package policy (§8: only chains the package allows
    /// are ever offered or honoured) — this never bypasses §6.
    std::optional<std::string> chain_override;
    /// True when .LEXE already placed us inside the terminal it chose for a
    /// console application; prevents an infinite terminal-spawning loop.
    bool attached_terminal = false;
    /// Whether .LEXE may open a terminal for a console application that was
    /// launched without one (Definitive Architecture §14.4).
    ///
    /// Defaults to FALSE deliberately: opening a window is a user-facing
    /// frontend behaviour, not something a library call should do behind its
    /// caller's back. `lexe run` and the graphical frontends opt IN; embedders,
    /// automation and tests get the quiet behaviour (output captured and
    /// returned) without having to remember to opt out.
    bool allow_terminal_spawn = false;
    /// Detach and return immediately instead of waiting (service mode, and
    /// GUI launches from a desktop handler that must not block).
    bool detach = false;
    /// Wait for the application to exit even when its manifest declares
    /// `launch.mode: "service"`, which is otherwise detached by declaration.
    /// This is for watching a service run — a developer's `--wait`, not a
    /// behaviour any handler should pick. It never overrides `detach`.
    bool wait_for_exit = false;
};

/// What actually happened. This is the "record execution report" box of §7.
struct ExecutionReport {
    std::string id;
    std::string version;
    std::string chain;        // the execution chain id actually used
    std::string chain_reason; // why that chain
    std::string launch_mode;  // declared gui / console / service
    bool mission_critical = false;
    bool started = false;     // the application was actually executed
    bool detached = false;    // started and deliberately not waited for
    int exit_code = -1;
    std::optional<int> signal;
    std::string isolation_summary; // truthful control summary
    /// Present only when a structured error record was written (§9).
    std::optional<ErrorRecord> error;

    /// True when the application ran and reported success. Exit code 0 is
    /// success even when nothing appeared on screen (§14.4).
    bool succeeded() const { return started && exit_code == 0; }
};

/// Run the installed application described by `request`.
///
/// Throws NotFoundError when the app is not installed, LaunchError /
/// IsolationError / TrustError for a refused launch. Whenever it throws, a
/// structured error record has already been written to the error store.
ExecutionReport run_application(const Paths& paths, const RunRequest& request);

/// Backwards-compatible convenience used by the CLI and the frontends: run
/// `id` with `args` and return the child's exit code.
int run_app(const Paths& paths, const std::string& id,
            const std::vector<std::string>& args);

/// Resolve how `id` WOULD run, without running it (`lexe compat <id>`, and the
/// Compatibility page of the consumer frontend). Throws NotFoundError when the
/// application is not installed.
ChainResolution resolve_application_chain(const Paths& paths,
                                          const std::string& id);

/// The terminal emulator .LEXE would use for a console application on this
/// host, or "" when none is available. Exposed for diagnostics (`lexe doctor`).
std::string detect_terminal_emulator();

} // namespace lexe

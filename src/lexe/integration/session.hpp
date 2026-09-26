#pragma once
// session — systemd `--user` unit generation for `launch.mode: "service"`
// applications (docs/SERVICES.md).
//
// PURE CONTENT GENERATION, and nothing else. Every function here is a function of
// its arguments: it computes the text of a unit file and the path that unit
// belongs at. It writes nothing, starts nothing, and talks to no service manager.
//
// That split is the same one `integration/desktop` has, and for the same reason:
// the text is the interesting, testable part, and it can be exercised on any
// platform — including one with no systemd at all — while the side effects live in
// one place that owns recording and repair.
//
// Actuating a unit (writing it, `daemon-reload`, enable, start, stop, disable) is
// `SessionManager` in session_manager.hpp. Recording it as a durable artifact so
// `lexe doctor` can name and repair it is `DesktopIntegration`, via
// `ArtifactKind::SessionUnit`.
//
// -------------------------------------------------------------------------
// Why a unit at all, when .LEXE already supervises a detached service
// -------------------------------------------------------------------------
//
// It already does, minimally: a detached `lexe` supervisor holds the version lease
// and reaps the sandbox. What it deliberately does not do is restart a crashed
// service, start one at login, or report status — and a runtime that did those
// things without being asked would be a session manager competing with the one
// the host already has.
//
// So there are two modes with exactly ONE supervisor each, never both at once:
//
//   .LEXE-supervised   the default. `lexe run`. No restart, no status, no login.
//   session-managed    opt in. systemd owns lifetime, restart, logging, login.
//
// The unit below invokes `lexe run <id> --wait`, and the `--wait` is the entire
// reason this works. Without it the runtime detaches by declaration and `lexe run`
// returns immediately; a Type=simple unit would see its main process exit, decide
// the service had died, and restart it forever while the real payload kept
// running. `--wait` makes the `lexe` process itself the unit's MAINPID for the
// payload's whole lifetime, and restores bubblewrap's `--die-with-parent` so
// `systemctl --user stop` tears the sandbox down through the mechanism systemd
// already uses.

#include "lexe/base/paths.hpp"
#include "lexe/package/manifest.hpp"

#include <string>

namespace lexe::session {

/// Everything the unit text depends on, gathered so the generator stays pure.
struct UnitInputs {
    /// The application. Only `id`, `name` and `launch_mode` are read.
    Manifest manifest;
    /// Absolute path of the `lexe` binary the unit should invoke.
    ///
    /// Resolved by the caller, never assumed: a unit that hard-codes
    /// `/usr/bin/lexe` is wrong on a machine where the runtime lives anywhere
    /// else, and a unit that says bare `lexe` is wrong because a systemd `--user`
    /// unit does not inherit the invoking shell's PATH.
    std::string runtime_path;
    /// `LEXE_HOME` to pin into the unit, or empty to inherit the default.
    ///
    /// A unit is generated against the installation root it was enabled from. Set
    /// only when that root is an override, so an ordinary unit stays portable
    /// across a home directory that moves — and so the test suites, which run
    /// against a scratch root, can exercise any of this at all.
    std::string lexe_home;
};

/// The unit name, e.g. `lexe-com.example.daemon.service`.
///
/// Prefixed because the units in a user's `~/.config/systemd/user` are a shared
/// namespace: an application id alone could collide with something the user or
/// their distribution put there, and a name that says who owns it is also the
/// name `lexe doctor` can recognise as ours.
std::string unit_name(const std::string& app_id);

/// Where that unit belongs: `<XDG_CONFIG_HOME>/systemd/user/<unit_name>`.
std::string unit_path(const Paths& paths, const std::string& app_id);

/// The complete `.service` file text.
///
/// Throws lexe::Error when the manifest does not declare
/// `launch.mode: "service"`. Generating a unit for a GUI or console application
/// would be answering a question nobody asked: those modes have no lifetime for a
/// service manager to own, and a unit that restarted a GUI application on exit
/// would fight the user closing its window.
std::string unit_text(const UnitInputs& inputs);

/// True when this application may be session-managed at all.
///
/// Exposed so a frontend can hide or explain the control rather than offering it
/// and then failing. The rule is only the declared launch mode — enablement is a
/// user decision and no manifest field asks for it.
bool is_session_manageable(const Manifest& manifest);

/// Why `is_session_manageable` said no, for a frontend to show. Empty when it
/// said yes.
std::string session_unmanageable_reason(const Manifest& manifest);

} // namespace lexe::session

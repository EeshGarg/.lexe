#pragma once
// session_manager — talking to `systemd --user` (docs/SERVICES.md).
//
// The side-effecting half of session integration. `session.hpp` computes the unit
// text; this writes it, reloads the manager, enables, disables, and reports what
// both sides currently believe.
//
// Kept behind an interface with a probe, for the same reason `IsolationBackend`
// is: a host may have no session manager at all, and the honest answer then is a
// reported unavailability with a reason, not a crash and not a pretence. Every
// call goes through argv arrays — never a shell — so an application id can never
// become part of a command line.
//
// It does exactly four things and deliberately not a fifth: it does NOT enable
// lingering (`loginctl enable-linger`). That changes the user's session policy
// rather than anything about an application, and .LEXE does not make that decision
// on their behalf.

#include "lexe/base/paths.hpp"
#include "lexe/package/manifest.hpp"

#include <memory>
#include <string>
#include <vector>

namespace lexe::session {

/// Whether a session manager can be talked to here, and why not when it cannot.
enum class ManagerStatus {
    Available,       // a user session manager is running and responded
    NotInstalled,    // no systemctl on this host
    NoUserSession,   // systemctl exists but there is no running user session
    Unsupported,     // not a platform with a session manager at all (Windows)
};
const char* to_string(ManagerStatus s);

struct ManagerCapabilities {
    ManagerStatus status = ManagerStatus::Unsupported;
    std::string detail;          // truthful reason, always populated
    std::string manager_version; // e.g. "systemd 255", empty when unknown
};

/// What both sides believe about one application, which can disagree — and when
/// they do, that disagreement is the thing a user needs told.
struct SessionState {
    bool unit_present = false;   // the generated unit file exists on disk
    bool unit_recorded = false;  // .LEXE recorded it in integration.json
    bool enabled = false;        // systemd will start it at login
    bool active = false;         // systemd says it is running now
    /// A `.LEXE`-supervised copy is running OUTSIDE systemd — i.e. someone ran
    /// `lexe run` while a unit also exists. Detected by the version lease, which
    /// is the only liveness signal the runtime has.
    bool lexe_supervised_running = false;
    std::string unit_name;
    std::string unit_path;
    std::string detail;          // systemd's own words when it has any
};

class SessionManager {
  public:
    virtual ~SessionManager() = default;

    /// Cheap, cached probe. Never throws.
    virtual ManagerCapabilities capabilities() const = 0;

    /// Write the unit, reload, and enable it. Returns the unit path.
    ///
    /// Does NOT start it: enabling says "at login", starting says "now", and
    /// conflating them would surprise someone who enabled a service they were not
    /// ready to run. `lexe service enable --now` is how you ask for both.
    ///
    /// Throws when no manager is available, or when the manifest does not declare
    /// `launch.mode: "service"`.
    virtual std::string enable(const Manifest& manifest,
                              const std::string& runtime_path,
                              bool start_now) = 0;

    /// Stop, disable, and delete the unit. Idempotent: disabling something that
    /// was never enabled succeeds quietly, because the end state is what was
    /// asked for.
    virtual void disable(const std::string& app_id) = 0;

    /// What is true right now, from both sides.
    virtual SessionState state(const std::string& app_id) const = 0;

    /// Stop a running unit without disabling it. Used by uninstall, which must
    /// stop a service before removing the application out from under it.
    virtual void stop(const std::string& app_id) = 0;
};

/// The manager for this host. Returns a null implementation that reports
/// `Unsupported`/`NotInstalled` rather than nullptr, so callers never branch on
/// existence — only on capabilities.
std::unique_ptr<SessionManager> make_session_manager(const Paths& paths);

} // namespace lexe::session

// isolation — the shared runtime isolation abstraction used by the launcher
// (runtime-trust WS7). Turns approved permission metadata into truthful
// operating-system enforcement on Linux (via bubblewrap), and fails CLOSED
// whenever a required control cannot be enforced.
//
// The design separates PURE, testable policy from platform execution:
//   * build_plan()          request + capabilities  -> deterministic plan
//   * sanitize_environment() request                -> safe env allowlist
//   * render_bwrap_argv()    plan                    -> the exact argv to exec
// and an IsolationBackend that PROBES capabilities and RUNS a plan. A fake
// backend gives deterministic cross-platform tests; the real Linux backend is
// bubblewrap. Nothing here claims a control is enforced unless the backend can
// actually establish it — the control-state map records the truth.

#pragma once

#include "core/paths.hpp"

#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lexe {

/// The individual isolation controls the launcher tries to establish.
enum class IsolationControl {
    AppRootReadOnly,      // installed version bound read-only
    PrivateData,          // private writable persistent data root
    PrivateCache,         // private writable cache root
    PrivateTemp,          // private writable ephemeral temp
    HomeHidden,           // the user's real home is not visible
    NetworkDenied,        // no network access (permission absent)
    EnvironmentSanitized, // environment cleared to a safe allowlist
    NoNewPrivileges,      // setuid/privilege escalation prevented
    PidNamespace,         // private PID namespace
};

/// The truthful state of a control for a given launch.
enum class ControlState {
    Enforced,     // the OS actually establishes it
    Advisory,     // recorded/displayed but NOT enforced by the OS
    NotApplicable,// e.g. NetworkDenied when network IS permitted
    Unsupported,  // the platform/backend cannot do it
    SetupFailed,  // it was required but could not be established
};

/// Overall backend capability, from a real probe (not "binary present").
enum class CapabilityStatus {
    Available,          // a probe sandbox ran successfully
    PartiallyAvailable, // some but not all required features work
    Unavailable,        // no usable backend on this host
    PolicyUnsupported,  // the platform has no isolation backend at all
    SetupFailed,        // the probe itself errored
};

std::string to_string(IsolationControl c);
std::string to_string(ControlState s);
std::string to_string(CapabilityStatus s);

/// What the backend can actually do, determined by a bounded runtime probe.
struct IsolationCapabilities {
    CapabilityStatus status = CapabilityStatus::Unavailable;
    bool backend_present = false;    // the backend executable exists
    bool user_namespaces = false;    // an unprivileged sandbox ran
    bool network_namespaces = false; // --unshare-net worked in the probe
    bool bind_mounts = false;        // ro/rw binds worked in the probe
    std::string detail;              // human-readable reason / missing feature
};

/// A single bind mount in a plan. `optional` binds are skipped by the backend
/// when the host source is absent (e.g. distro-specific /etc files).
struct BindMount {
    std::string host;
    std::string sandbox;
    bool read_only = true;
    bool optional = false;
};

/// Everything the launcher knows about the app to be isolated. Paths are
/// installer-owned and already validated by the caller.
struct IsolationRequest {
    std::string app_id;
    std::filesystem::path app_root;   // read-only active version dir
    std::filesystem::path entrypoint; // absolute, inside app_root
    std::vector<std::string> args;    // exact app args (argv, never a shell)
    std::filesystem::path data_root;  // private persistent (host path)
    std::filesystem::path cache_root; // private cache (host path)
    bool network_allowed = false;     // "network" permission approved
    bool gui = false;                 // needs a display (advisory in 0.1)
    std::map<std::string, std::string> inherited_env; // caller env (to sanitize)
};

/// A deterministic, inspectable plan. The backend renders it to a command line;
/// tests inspect it directly.
struct IsolationPlan {
    std::vector<BindMount> binds;
    std::vector<std::string> tmpfs;   // sandbox tmpfs mount points (private temp)
    std::vector<std::pair<std::string, std::string>> symlinks; // sandbox symlinks
    std::map<std::string, std::string> env; // sanitized environment (allowlist)
    bool network_shared = false;      // false => the net namespace is unshared
    std::string working_dir;          // sandbox chdir (never the caller's cwd)
    std::vector<std::string> app_argv;// entrypoint + args, inside the sandbox
    std::map<IsolationControl, ControlState> controls; // what WILL be enforced
};

/// The outcome of running a plan.
struct IsolationResult {
    int exit_code = -1;
    std::map<IsolationControl, ControlState> enforced;
};

// ------------------------------------------------------------- pure policy

/// Sandbox-internal mount points for the private writable roots (fixed, so the
/// host layout is not exposed to the application).
inline constexpr const char* kSandboxData = "/run/lexe/data";
inline constexpr const char* kSandboxCache = "/run/lexe/cache";
inline constexpr const char* kSandboxTemp = "/tmp";

/// Build the safe environment for `req`: clears everything and sets only HOME,
/// PATH, TMPDIR and LEXE_APP_* to sandbox values. Dangerous variables
/// (LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH, …) are simply never included, so
/// they are stripped. Pure.
std::map<std::string, std::string>
sanitize_environment(const IsolationRequest& req);

/// Build a deterministic isolation plan from a request and probed capabilities.
/// Decides network sharing, the read-only/writable binds, the sanitized env,
/// and the control-state map. Throws IsolationError (fail closed) when a
/// REQUIRED control cannot be enforced — e.g. network denial is required but
/// network namespaces are unavailable. Pure (no filesystem/process effects).
IsolationPlan build_plan(const IsolationRequest& req,
                         const IsolationCapabilities& caps);

/// Render a plan to a bubblewrap argv (the exact command to exec). Pure and
/// deterministic; app arguments are passed as argv elements after `--`, never
/// interpolated into a shell.
std::vector<std::string> render_bwrap_argv(const IsolationPlan& plan,
                                           const std::string& bwrap_path);

// ------------------------------------------------------------- backends

class IsolationBackend {
public:
    virtual ~IsolationBackend() = default;
    /// A fresh bounded probe of what this backend can enforce right now.
    virtual IsolationCapabilities capabilities() const = 0;
    /// Execute the plan. Throws IsolationError on setup failure — NEVER falls
    /// back to direct execution.
    virtual IsolationResult run(const IsolationPlan& plan) = 0;
    virtual std::string name() const = 0;
};

/// The isolation backend for this platform: bubblewrap on Linux, otherwise a
/// backend reporting PolicyUnsupported. `paths` supplies runtime-root
/// locations; a probe cache dir may be created under it.
std::unique_ptr<IsolationBackend> make_isolation_backend(const Paths& paths);

/// A backend for deterministic, cross-platform tests: it returns preset
/// capabilities, records the plan it was asked to run, and either returns a
/// preset exit code or throws IsolationError (never executing anything).
class FakeIsolationBackend : public IsolationBackend {
public:
    explicit FakeIsolationBackend(IsolationCapabilities caps)
        : caps_(std::move(caps)) {}
    IsolationCapabilities capabilities() const override { return caps_; }
    IsolationResult run(const IsolationPlan& plan) override;
    std::string name() const override { return "fake"; }

    bool fail_setup = false; // when true, run() throws IsolationError
    int exit_code = 0;       // otherwise run() returns this
    bool ran = false;        // set true the moment run() is entered
    IsolationPlan last_plan; // the plan run() received

private:
    IsolationCapabilities caps_;
};

} // namespace lexe

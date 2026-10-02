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

#include <cstdio>

#include "lexe/base/paths.hpp"

#include <filesystem>
#include <map>
#include <memory>
#include <optional>
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
    DisplayIsolated,      // no display server socket is reachable
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
    /// The application declared launch.mode "gui" (Definitive Architecture
    /// §14.4) and therefore needs the session's display server. This is a
    /// DELIBERATE, declared reduction of isolation: the display socket is the
    /// one host resource a graphical application cannot do without. It is
    /// granted only when the manifest declares a GUI launch mode, it is
    /// reported truthfully in the control map (DisplayIsolated becomes
    /// NotApplicable, never silently "enforced"), and nothing else about the
    /// session — no D-Bus, no home, no network — comes with it.
    bool gui = false;
    /// This request is an install-time BUILD of a portable package, not a
    /// launch (Definitive Architecture §5/§7, FORMAT-0.1 §6.9). It is the same
    /// sandbox with three deliberate differences:
    ///
    ///   * `app_root` is the BUILD TREE and is bound WRITABLE — a build that
    ///     cannot write its own outputs is not a build. AppRootReadOnly is
    ///     reported NotApplicable, never "enforced";
    ///   * the network is denied unconditionally. `network_allowed` is ignored,
    ///     because a build that downloads is fetching unsigned code onto the
    ///     user's machine at install time, behind a signature that says nothing
    ///     about what was fetched;
    ///   * `gui` is ignored — nothing being compiled has any business reaching
    ///     the session's display.
    ///
    /// The build still runs UNPRIVILEGED, in the same user namespace, with the
    /// same sanitized environment and the same hidden home. Approval authorizes
    /// the OPERATION; it never gives build code any authority the launcher
    /// would not have granted the application itself.
    bool build = false;
    /// Absolute host paths of the compatibility-layer executables this launch
    /// will exec through (the resolved chain's argv prefix — Wine, Proton,
    /// FEX, Box64, …). Empty for the native chain, which is the whole point of
    /// the native chain.
    ///
    /// They have to be reachable INSIDE the sandbox or the chain cannot run at
    /// all. Distribution packages put them under /usr, which is already bound
    /// read-only; anything installed elsewhere (/opt, a Steam Proton tree, a
    /// user-local build) is not, so it is bound here. The binds are read-only
    /// and optional: a compatibility layer gets no more authority than the
    /// application it is running.
    std::vector<std::string> compatibility_paths;
    /// Sandbox path of the private per-user runtime directory to establish,
    /// normally `sandbox_runtime_dir_for_current_user()`. Empty means none —
    /// which is what the pure tests use, so a plan stays independent of the
    /// uid the suite happens to run as.
    std::string private_runtime_dir;
    /// Environment the resolved execution chain REQUIRES, as name -> value.
    /// Merged into the allowlisted environment below. A chain cannot reach the
    /// caller environment this way — it can only ADD names it declares, with
    /// values it chose, which are sandbox paths.
    std::map<std::string, std::string> chain_env;
    std::map<std::string, std::string> inherited_env; // caller env (to sanitize)
};

/// A deterministic, inspectable plan. The backend renders it to a command line;
/// tests inspect it directly.
struct IsolationPlan {
    std::vector<BindMount> binds;
    /// Binds that must be applied AFTER the minimal /dev is established (a
    /// /dev/... bind placed before it would simply be shadowed). Used for GPU
    /// device nodes when a GUI application is granted display access.
    std::vector<BindMount> dev_binds;
    std::vector<std::string> tmpfs;   // sandbox tmpfs mount points (private temp)
    std::vector<std::pair<std::string, std::string>> symlinks; // sandbox symlinks
    std::map<std::string, std::string> env; // sanitized environment (allowlist)
    bool network_shared = false;      // false => the net namespace is unshared
    std::string working_dir;          // sandbox chdir (never the caller's cwd)
    std::vector<std::string> app_argv;// entrypoint + args, inside the sandbox
    std::map<IsolationControl, ControlState> controls; // what WILL be enforced
    /// Capture the child's stdout/stderr instead of letting it inherit ours.
    /// Used when .LEXE must be able to put the output into a structured error
    /// record (Definitive Architecture §9) — e.g. a console application
    /// launched from the desktop with no terminal available.
    bool capture_output = false;
    /// With capture_output, write the child's bytes THROUGH to these streams as
    /// they arrive instead of holding them until exit. Null keeps them held.
    ///
    /// The launcher sets these to its own stdout/stderr. Holding the output
    /// meant the launcher's memory grew with it — 512 MiB of output cost about
    /// 1 GB of RSS — so a program that legitimately streams took the launcher
    /// with it. See util::RunOptions::tee_stdout.
    std::FILE* tee_stdout = nullptr;
    std::FILE* tee_stderr = nullptr;
    /// Cap on the copy RETAINED for the error record. 0 means no cap.
    std::size_t max_retained_bytes = 0;
    /// Start and return, instead of waiting for the application to exit
    /// (`launch.mode: "service"`, §5). The sandbox must then NOT die with the
    /// process that started it, so the rendered argv omits `--die-with-parent`
    /// — a detached launch whose sandbox is torn down the moment `lexe run`
    /// returns is not a detached launch.
    bool detach = false;
    /// A lock file the detached supervisor holds for the application's
    /// lifetime (the launch lease). Meaningless without `detach`.
    std::string supervisor_lock_file;
};

/// The outcome of running a plan.
struct IsolationResult {
    int exit_code = -1;
    std::map<IsolationControl, ControlState> enforced;
    std::string stdout_text; // only when the plan requested capture; a SAMPLE
                             // when max_retained_bytes capped it
    std::string stderr_text;
    std::uint64_t stdout_total_bytes = 0; // what the child actually wrote
    std::uint64_t stderr_total_bytes = 0;
    bool stdout_truncated = false;
    bool stderr_truncated = false;
    std::optional<int> signal; // set when the child was killed by a signal
    /// The application was STARTED and deliberately not waited for. There is
    /// no exit code to report and none is invented: `exit_code` stays 0
    /// meaning "started", which is not the same claim as "succeeded".
    bool detached = false;
};

// ------------------------------------------------------------- pure policy

/// Sandbox-internal mount points for the private writable roots (fixed, so the
/// host layout is not exposed to the application).
inline constexpr const char* kSandboxData = "/run/lexe/data";
inline constexpr const char* kSandboxCache = "/run/lexe/cache";
inline constexpr const char* kSandboxTemp = "/tmp";
/// Fixed sandbox location of the session runtime directory when a GUI
/// application is granted display access. The host's real XDG_RUNTIME_DIR is
/// never exposed — only the individual display socket is bound in here.
inline constexpr const char* kSandboxRuntime = "/run/lexe/session";
/// Where a Proton chain keeps its compatibility prefix, inside the sandbox.
///
/// Under the application own private data root, deliberately: Wine prefix
/// already lands there because HOME is redirected to it, and Proton state is
/// the application state for exactly the same reason. It also means uninstalling
/// `lexe purge` of the application removes the prefix, and that nothing of the
/// user real Steam installation is bound, named, or reachable from inside.
///
/// Proton does NOT create this directory: with it missing, wine fails with
/// "chdir to <path>/pfx : No such file or directory" and exits 1. It is
/// established from ExecutionChain::required_data_dirs before launch.
inline constexpr const char* kSandboxProtonPrefix = "/run/lexe/data/.proton";
/// STEAM_COMPAT_CLIENT_INSTALL_PATH. Proton requires the variable to be SET —
/// it dies with a Python KeyError otherwise — but does not require the path to
/// exist, and nothing in the launch path needs a real Steam client. So this
/// names a location inside the private prefix rather than the user Steam
/// installation.
inline constexpr const char* kSandboxProtonSteam =
    "/run/lexe/data/.proton/steam";

/// The conventional per-user runtime directory (`/run/user/<uid>`) as the
/// sandbox should see it: a PRIVATE, empty tmpfs, never the host's.
///
/// Software that needs a runtime directory often computes this path from its
/// own uid and ignores `XDG_RUNTIME_DIR` entirely — Wine is the case that
/// forced this to exist: with no `/run/user/<uid>` it aborts during prefix
/// setup, and pointing `XDG_RUNTIME_DIR` somewhere else does not help.
///
/// Providing an empty private one costs no isolation: it contains nothing of
/// the user's session (no Wayland socket, no D-Bus, no keyring), it is
/// discarded with the sandbox, and the application could already write to
/// /tmp. What it buys is that "this program needs a runtime directory" stops
/// being an unexplained abort. Returns "" on platforms without one.
std::string sandbox_runtime_dir_for_current_user();

/// Build the safe environment for `req`: clears everything and sets only HOME,
/// PATH, TMPDIR and LEXE_APP_* to sandbox values. Dangerous variables
/// (LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH, …) are simply never included, so
/// they are stripped. Pure.
std::map<std::string, std::string>
sanitize_environment(const IsolationRequest& req);

/// Host locations of the system TLS trust store, bound read-only into the
/// sandbox ONLY when the `network` permission is granted.
///
/// The sandbox's `/etc` is an allowlist, and the allowlist was chosen for
/// dynamic linking and name resolution. The trust store was not on it, so a
/// granted `network` permission produced a network on which no ordinary Linux
/// TLS client could verify a certificate. Measured on Ubuntu 24.04 in a
/// sandbox built from the argv render_bwrap_argv() produces for a
/// network-permitted console launch: `http://example.com/` returned 200 (so
/// the network and DNS both worked) and `https://example.com/` failed with
/// curl exit 77, "error setting certificate file" — while the same URL with
/// `-k`, or with a CA bundle shipped in the payload, returned 200. That is a
/// granted permission silently not working, which is the opposite of this
/// runtime's fail-closed posture. Whether the file is reachable at all,
/// through the real launcher and with and without the permission, is asserted
/// in tests/test_etc_surface.cpp.
///
/// Gated on `network` rather than always bound, for the same reason
/// `resolv.conf` and `hosts` are: the permission is what makes a trust store
/// meaningful, and an application with no network has no use for one. The
/// contents are public CA root certificates — the same bytes on every machine
/// of a given distribution — so this widens the `/etc` surface by nothing
/// secret. Every entry is an OPTIONAL bind: a host that lacks one skips it.
///
/// Verified on Debian/Ubuntu (`/etc/ssl/certs`). The Fedora/RHEL and
/// openSUSE/Arch locations are included from their documented layout, not from
/// a measurement on this host, and are labelled as such in docs/ISOLATION.md.
std::vector<std::string> tls_trust_store_paths();

/// Whether `sysroot` (in production "/") actually holds a system TLS trust
/// store. Separate from the bind list because the binds are optional and a
/// missing source is silently skipped — which is exactly the failure this
/// function exists to make loud.
bool tls_trust_store_present(const std::filesystem::path& sysroot);

/// The one-line warning to print before running `plan`, or "" when there is
/// nothing to warn about.
///
/// Non-empty only when the plan shares the host network (the `network`
/// permission was granted) and `sysroot` has no trust store to bind. Pure
/// given `sysroot`, so it can be tested against a fabricated tree on any
/// platform instead of only on a host that happens to be misconfigured.
std::string tls_trust_store_warning(const IsolationPlan& plan,
                                    const std::filesystem::path& sysroot);

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

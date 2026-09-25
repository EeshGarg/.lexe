// isolation — see isolation.hpp. The pure policy/env/render functions are
// platform-neutral; the bubblewrap backend is Linux-only (behind _WIN32 guards)
// so MSVC keeps compiling with a PolicyUnsupported backend.

#include "core/isolation.hpp"

#include "core/error.hpp"
#include "core/util.hpp"

#include <array>
#include <optional>
#include <system_error>
#include <utility>

namespace fs = std::filesystem;

namespace lexe {

std::string to_string(IsolationControl c) {
    switch (c) {
        case IsolationControl::AppRootReadOnly: return "app-root-read-only";
        case IsolationControl::PrivateData: return "private-data";
        case IsolationControl::PrivateCache: return "private-cache";
        case IsolationControl::PrivateTemp: return "private-temp";
        case IsolationControl::HomeHidden: return "home-hidden";
        case IsolationControl::NetworkDenied: return "network-denied";
        case IsolationControl::EnvironmentSanitized: return "environment-sanitized";
        case IsolationControl::NoNewPrivileges: return "no-new-privileges";
        case IsolationControl::PidNamespace: return "pid-namespace";
        case IsolationControl::DisplayIsolated: return "display-isolated";
    }
    return "?";
}

std::string to_string(ControlState s) {
    switch (s) {
        case ControlState::Enforced: return "enforced";
        case ControlState::Advisory: return "advisory";
        case ControlState::NotApplicable: return "not-applicable";
        case ControlState::Unsupported: return "unsupported";
        case ControlState::SetupFailed: return "setup-failed";
    }
    return "?";
}

std::string to_string(CapabilityStatus s) {
    switch (s) {
        case CapabilityStatus::Available: return "available";
        case CapabilityStatus::PartiallyAvailable: return "partially-available";
        case CapabilityStatus::Unavailable: return "unavailable";
        case CapabilityStatus::PolicyUnsupported: return "policy-unsupported";
        case CapabilityStatus::SetupFailed: return "setup-failed";
    }
    return "?";
}

// -------------------------------------------------------------- pure policy

std::map<std::string, std::string>
sanitize_environment(const IsolationRequest& req) {
    // Allowlist ONLY. Everything the caller had (LD_PRELOAD, LD_LIBRARY_PATH,
    // PYTHONPATH, DBUS_SESSION_BUS_ADDRESS, proxies, secrets, …) is dropped by
    // omission — the backend clears the environment and sets only these.
    std::map<std::string, std::string> env;
    env["HOME"] = kSandboxData;
    env["PATH"] = "/usr/bin:/bin";
    env["TMPDIR"] = kSandboxTemp;
    env["LEXE_APP_ID"] = req.app_id;
    env["LEXE_APP_DATA"] = kSandboxData;
    env["LEXE_APP_CACHE"] = kSandboxCache;

    if (req.build) {
        // A build gets a stable, minimal environment and nothing of the
        // session. LC_ALL/LANG are pinned to C so compiler diagnostics that
        // end up in an error record read the same on every machine, and
        // SOURCE_DATE_EPOCH is not inherited from whatever the caller had.
        env["LC_ALL"] = "C";
        env["LANG"] = "C";
        env["LEXE_BUILD"] = "1";
        return env;
    }

    // Display variables are forwarded ONLY for a declared GUI launch mode
    // (Definitive Architecture §14.4), and even then they are rewritten to the
    // fixed sandbox paths so the host's real runtime directory layout is never
    // exposed. A console or service application still gets no display at all.
    if (req.gui) {
        const auto host = [&](const char* name) -> std::string {
            const auto it = req.inherited_env.find(name);
            return it == req.inherited_env.end() ? std::string() : it->second;
        };
        const std::string wayland = host("WAYLAND_DISPLAY");
        const std::string display = host("DISPLAY");
        if (!wayland.empty()) {
            env["XDG_RUNTIME_DIR"] = kSandboxRuntime;
            // A bare socket name resolves inside XDG_RUNTIME_DIR; an absolute
            // WAYLAND_DISPLAY is remapped to the sandbox location.
            env["WAYLAND_DISPLAY"] = fs::path(wayland).filename().string();
        }
        if (!display.empty()) {
            env["DISPLAY"] = display;
        }
        // Toolkit/session hints that only affect rendering, never authority.
        for (const char* name :
             {"XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "GDK_BACKEND",
              "QT_QPA_PLATFORM", "LANG", "LC_ALL", "LC_MESSAGES"}) {
            const std::string value = host(name);
            if (!value.empty()) env[name] = value;
        }
    }
    return env;
}

namespace {

/// The host path of the Wayland display socket, or "" when there is none.
std::string wayland_socket_path(const IsolationRequest& req) {
    const auto find = [&](const char* name) -> std::string {
        const auto it = req.inherited_env.find(name);
        return it == req.inherited_env.end() ? std::string() : it->second;
    };
    const std::string display = find("WAYLAND_DISPLAY");
    if (display.empty()) return {};
    if (!display.empty() && display.front() == '/') return display; // absolute
    const std::string runtime = find("XDG_RUNTIME_DIR");
    if (runtime.empty()) return {};
    return (fs::path(runtime) / display).generic_string();
}

/// The host path of the X11 display socket for `DISPLAY`, or "".
std::string x11_socket_path(const IsolationRequest& req) {
    const auto it = req.inherited_env.find("DISPLAY");
    if (it == req.inherited_env.end() || it->second.empty()) return {};
    const std::string display = it->second;
    // ":0", ":0.0", "unix:0" -> screen 0 socket /tmp/.X11-unix/X0. A remote
    // "host:0" DISPLAY has no local socket and is deliberately not supported:
    // it would need network access the sandbox does not grant.
    const std::size_t colon = display.rfind(':');
    if (colon == std::string::npos) return {};
    const std::string head = display.substr(0, colon);
    if (!head.empty() && head != "unix") return {};
    std::string number = display.substr(colon + 1);
    if (const std::size_t dot = number.find('.'); dot != std::string::npos) {
        number = number.substr(0, dot);
    }
    if (number.empty()) return {};
    for (const char c : number) {
        if (c < '0' || c > '9') return {};
    }
    return "/tmp/.X11-unix/X" + number;
}

} // namespace

IsolationPlan build_plan(const IsolationRequest& req,
                         const IsolationCapabilities& caps) {
    // Baseline requires an unprivileged user namespace and working bind mounts;
    // without them nothing below can be enforced, so fail closed.
    if (!caps.user_namespaces || !caps.bind_mounts) {
        throw IsolationError(
            "isolation: the baseline sandbox cannot be established "
            "(user namespaces / bind mounts unavailable): " + caps.detail);
    }

    IsolationPlan plan;

    // Read-only system view (merged-usr). /usr is required; the symlinks make
    // /bin, /lib, … resolve; the /etc entries are try-binds (may be absent or
    // themselves symlinks on some hosts).
    plan.binds.push_back({"/usr", "/usr", true});
    plan.symlinks = {{"usr/bin", "/bin"},
                     {"usr/lib", "/lib"},
                     {"usr/lib64", "/lib64"},
                     {"usr/sbin", "/sbin"}};
    for (const char* f :
         {"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
          "/etc/passwd", "/etc/group", "/etc/nsswitch.conf",
          "/etc/alternatives", "/etc/localtime"}) {
        plan.binds.push_back({f, f, /*read_only=*/true, /*optional=*/true});
    }

    // Network: denied by default (private, empty net namespace) unless the
    // "network" permission was approved. Denial REQUIRES a network namespace;
    // if the backend cannot provide one, fail closed rather than run unconfined.
    if (req.network_allowed && !req.build) {
        plan.network_shared = true;
        plan.controls[IsolationControl::NetworkDenied] =
            ControlState::NotApplicable;
        // Name resolution config only when networking is permitted.
        plan.binds.push_back({"/etc/resolv.conf", "/etc/resolv.conf", true, true});
        plan.binds.push_back({"/etc/hosts", "/etc/hosts", true, true});
    } else if (caps.network_namespaces) {
        plan.network_shared = false;
        plan.controls[IsolationControl::NetworkDenied] = ControlState::Enforced;
    } else if (req.build) {
        throw IsolationError(
            "isolation: a portable package's build must run with the network "
            "denied, but network-namespace isolation is unavailable on this "
            "host; refusing to compile with the network reachable");
    } else {
        throw IsolationError(
            "isolation: network denial is required (the application has no "
            "network permission) but network-namespace isolation is "
            "unavailable on this host; refusing to launch unconfined");
    }

    // Application root: bound at its real path, READ-ONLY (no self-modification).
    // Paths are rendered POSIX-style (the sandbox is Linux); on Linux this
    // equals string(), and it keeps the pure functions deterministic on any
    // host that runs the tests.
    const std::string app_root = req.app_root.generic_string();
    plan.binds.push_back({app_root, app_root, /*read_only=*/!req.build});
    // A build writes its outputs into this tree, so read-only would be a
    // contradiction rather than a control. Say that, instead of reporting a
    // control as enforced when the mount is writable.
    plan.controls[IsolationControl::AppRootReadOnly] =
        req.build ? ControlState::NotApplicable : ControlState::Enforced;

    // Compatibility layers the resolved chain will exec through. /usr is
    // already bound, so this only adds what lives outside it — a Proton tree
    // under ~/.steam, a hand-built FEX in /opt. The whole installation prefix
    // is bound, not just the executable, because a compatibility layer without
    // its own libraries and data is an executable that immediately fails.
    for (const std::string& path : req.compatibility_paths) {
        if (path.empty() || path.front() != '/') continue;
        if (path.rfind("/usr/", 0) == 0) continue; // already bound read-only
        const fs::path executable(path);
        fs::path bind = executable.parent_path();
        // `<prefix>/bin/<name>` is the conventional layout; bind `<prefix>`.
        if (bind.filename() == "bin" && bind.has_parent_path()) {
            bind = bind.parent_path();
        }
        const std::string host = bind.generic_string();
        if (host.empty() || host == "/") continue; // never bind the host root
        plan.binds.push_back({host, host, /*read_only=*/true,
                              /*optional=*/true});
    }

    // Private writable roots at fixed sandbox paths (host layout not exposed).
    plan.binds.push_back({req.data_root.generic_string(), kSandboxData, false});
    plan.binds.push_back({req.cache_root.generic_string(), kSandboxCache, false});
    plan.tmpfs = {kSandboxTemp};
    plan.controls[IsolationControl::PrivateData] = ControlState::Enforced;
    plan.controls[IsolationControl::PrivateCache] = ControlState::Enforced;
    plan.controls[IsolationControl::PrivateTemp] = ControlState::Enforced;

    // Home is never bound → not visible.
    plan.controls[IsolationControl::HomeHidden] = ControlState::Enforced;

    // Display access (Definitive Architecture §14.4). A GUI application gets
    // exactly ONE extra thing: the session's display socket. Not the runtime
    // directory, not D-Bus, not the home directory. When the manifest declares
    // any other launch mode, no display socket is reachable at all and the
    // control is reported as enforced — truthfully, because it is.
    if (req.gui && !req.build) {
        bool granted = false;
        if (const std::string wayland = wayland_socket_path(req);
            !wayland.empty()) {
            // Writable: connecting to a unix socket requires write access.
            plan.binds.push_back(
                {wayland,
                 std::string(kSandboxRuntime) + "/" +
                     fs::path(wayland).filename().string(),
                 /*read_only=*/false, /*optional=*/true});
            granted = true;
        }
        if (const std::string x11 = x11_socket_path(req); !x11.empty()) {
            plan.binds.push_back({x11, x11, /*read_only=*/false,
                                  /*optional=*/true});
            granted = true;
        }
        // Font configuration and the GPU nodes: rendering resources only.
        for (const char* f : {"/etc/fonts", "/etc/machine-id", "/var/cache/fontconfig"}) {
            plan.binds.push_back({f, f, /*read_only=*/true, /*optional=*/true});
        }
        plan.dev_binds.push_back({"/dev/dri", "/dev/dri", /*read_only=*/false,
                                  /*optional=*/true});
        plan.controls[IsolationControl::DisplayIsolated] =
            granted ? ControlState::NotApplicable : ControlState::Enforced;
    } else {
        plan.controls[IsolationControl::DisplayIsolated] =
            ControlState::Enforced;
    }

    // Sanitized environment (allowlist) + a safe writable working directory
    // that is NOT the caller's cwd.
    plan.env = sanitize_environment(req);
    // A build runs IN the tree it is building; everything else runs in its own
    // private data root and never sees the installed tree as a working dir.
    plan.working_dir = req.build ? app_root : std::string(kSandboxData);
    plan.controls[IsolationControl::EnvironmentSanitized] =
        ControlState::Enforced;
    // A failed build has to be explainable. Compiler diagnostics go into the
    // structured error record (Definitive Architecture §9) rather than onto
    // whatever terminal — possibly none — the install happened to run from.
    if (req.build) plan.capture_output = true;

    // The user namespace boundary prevents setuid privilege escalation; a
    // private PID namespace is unshared below.
    plan.controls[IsolationControl::NoNewPrivileges] = ControlState::Enforced;
    plan.controls[IsolationControl::PidNamespace] = ControlState::Enforced;

    // App argv: the exact entrypoint + args, as argv elements (never a shell).
    plan.app_argv.push_back(req.entrypoint.generic_string());
    plan.app_argv.insert(plan.app_argv.end(), req.args.begin(), req.args.end());

    return plan;
}

std::vector<std::string> render_bwrap_argv(const IsolationPlan& plan,
                                           const std::string& bwrap_path) {
    std::vector<std::string> a;
    a.push_back(bwrap_path);
    // Namespaces + session hardening.
    a.push_back("--unshare-user");
    a.push_back("--unshare-ipc");
    a.push_back("--unshare-uts");
    a.push_back("--unshare-cgroup");
    a.push_back("--unshare-pid");
    if (!plan.network_shared) a.push_back("--unshare-net");
    a.push_back("--new-session");
    a.push_back("--die-with-parent");

    // Clear the environment, then set only the allowlist.
    a.push_back("--clearenv");
    for (const auto& [k, v] : plan.env) {
        a.push_back("--setenv");
        a.push_back(k);
        a.push_back(v);
    }

    // Merged-usr symlinks.
    for (const auto& [target, link] : plan.symlinks) {
        a.push_back("--symlink");
        a.push_back(target);
        a.push_back(link);
    }

    // tmpfs mounts FIRST, so a later bind whose sandbox path lies under a tmpfs
    // (e.g. an app root under /tmp) layers on top and stays visible rather than
    // being shadowed by the tmpfs.
    for (const std::string& t : plan.tmpfs) {
        a.push_back("--tmpfs");
        a.push_back(t);
    }

    // Binds. Writable roots use --bind; required read-only binds use --ro-bind;
    // optional ones use --ro-bind-try so a missing host source is skipped.
    for (const BindMount& b : plan.binds) {
        if (!b.read_only) {
            a.push_back("--bind");
        } else if (b.optional) {
            a.push_back("--ro-bind-try");
        } else {
            a.push_back("--ro-bind");
        }
        a.push_back(b.host);
        a.push_back(b.sandbox);
    }

    // Minimal /proc and /dev, overlaid after the binds.
    a.push_back("--proc");
    a.push_back("/proc");
    a.push_back("--dev");
    a.push_back("/dev");

    // Device binds go AFTER --dev; placed before it they would be shadowed by
    // the minimal /dev that --dev establishes.
    for (const BindMount& b : plan.dev_binds) {
        a.push_back(b.optional ? "--dev-bind-try" : "--dev-bind");
        a.push_back(b.host);
        a.push_back(b.sandbox);
    }

    a.push_back("--chdir");
    a.push_back(plan.working_dir);

    a.push_back("--");
    a.insert(a.end(), plan.app_argv.begin(), plan.app_argv.end());
    return a;
}

// ------------------------------------------------------------- fake backend

IsolationResult FakeIsolationBackend::run(const IsolationPlan& plan) {
    ran = true;
    last_plan = plan;
    if (fail_setup) {
        throw IsolationError("isolation: (fake) backend setup failed");
    }
    IsolationResult result;
    result.exit_code = exit_code;
    result.enforced = plan.controls;
    return result;
}

// ------------------------------------------------------- platform backend

namespace {

/// Backend for platforms with no isolation support (e.g. Windows). It reports
/// PolicyUnsupported; the launcher treats that as "no isolation on this
/// platform" rather than a fail-closed failure.
class NullIsolationBackend : public IsolationBackend {
public:
    IsolationCapabilities capabilities() const override {
        IsolationCapabilities caps;
        caps.status = CapabilityStatus::PolicyUnsupported;
        caps.detail = "no runtime-isolation backend on this platform";
        return caps;
    }
    IsolationResult run(const IsolationPlan&) override {
        throw IsolationError(
            "isolation: no isolation backend on this platform");
    }
    std::string name() const override { return "none"; }
};

} // namespace

#ifndef _WIN32

namespace {

/// Locate the bubblewrap executable. The LEXE_BWRAP environment variable
/// overrides it (tests point it at a missing/broken path to simulate an
/// unavailable backend); an override that does not exist yields "" (not found).
std::string find_bwrap() {
    const std::optional<std::string> override = util::get_env("LEXE_BWRAP");
    if (override.has_value()) {
        std::error_code ec;
        if (!override->empty() && fs::exists(*override, ec)) return *override;
        return "";
    }
    for (const char* p : {"/usr/bin/bwrap", "/bin/bwrap"}) {
        std::error_code ec;
        if (fs::exists(p, ec)) return p;
    }
    return "";
}

/// The real Linux backend. Capability detection RUNS bubblewrap (a bounded
/// probe) — "binary present" is never treated as proof it works.
class LinuxBubblewrapBackend : public IsolationBackend {
public:
    IsolationCapabilities capabilities() const override {
        IsolationCapabilities caps;
        const std::string bwrap = find_bwrap();
        caps.backend_present = !bwrap.empty();
        if (!caps.backend_present) {
            caps.status = CapabilityStatus::Unavailable;
            caps.detail = "bubblewrap (bwrap) executable not found";
            return caps;
        }
        // Run a real minimal sandbox: unprivileged userns + read-only binds +
        // merged-usr symlinks + a dynamically-linked binary (/usr/bin/true).
        const auto probe = [&](bool unshare_net) -> bool {
            std::vector<std::string> argv = {
                bwrap,          "--unshare-user", "--ro-bind", "/usr", "/usr",
                "--symlink",    "usr/lib",        "/lib",      "--symlink",
                "usr/lib64",    "/lib64",         "--symlink", "usr/bin",
                "/bin",         "--proc",         "/proc",     "--dev",
                "/dev",         "--die-with-parent"};
            if (unshare_net) argv.push_back("--unshare-net");
            argv.push_back("/usr/bin/true");
            util::RunOptions o;
            o.capture_stdout = true; // swallow any output
            try {
                return util::run_process(argv, o).exit_code == 0;
            } catch (const Error&) {
                return false;
            }
        };
        caps.user_namespaces = probe(/*unshare_net=*/false);
        caps.bind_mounts = caps.user_namespaces; // the probe exercised ro-bind
        caps.network_namespaces =
            caps.user_namespaces && probe(/*unshare_net=*/true);
        if (caps.user_namespaces && caps.network_namespaces) {
            caps.status = CapabilityStatus::Available;
        } else if (caps.user_namespaces) {
            caps.status = CapabilityStatus::PartiallyAvailable;
            caps.detail = "network-namespace isolation unavailable";
        } else {
            caps.status = CapabilityStatus::Unavailable;
            caps.detail = "unprivileged user namespaces do not work here";
        }
        return caps;
    }

    IsolationResult run(const IsolationPlan& plan) override {
        // Re-resolve the backend immediately before launch; if it vanished
        // since planning, fail closed (never execute the app directly).
        const std::string bwrap = find_bwrap();
        if (bwrap.empty()) {
            throw IsolationError(
                "isolation: bubblewrap backend disappeared before launch");
        }
        const std::vector<std::string> argv = render_bwrap_argv(plan, bwrap);
        util::RunOptions o;
        // On a normal launch the application owns our stdout/stderr; capture
        // is requested only when .LEXE has to record the output itself.
        o.capture_stdout = plan.capture_output;
        o.capture_stderr = plan.capture_output;
        IsolationResult result;
        try {
            const util::ProcessResult process = util::run_process(argv, o);
            result.exit_code = process.exit_code;
            result.stdout_text = process.stdout_text;
            result.stderr_text = process.stderr_text;
            result.signal = process.signal;
        } catch (const Error& e) {
            throw IsolationError(
                std::string("isolation: backend execution failed: ") + e.what());
        }
        result.enforced = plan.controls;
        return result;
    }

    std::string name() const override { return "bubblewrap"; }
};

} // namespace

std::unique_ptr<IsolationBackend> make_isolation_backend(const Paths&) {
    return std::make_unique<LinuxBubblewrapBackend>();
}

#else // _WIN32

std::unique_ptr<IsolationBackend> make_isolation_backend(const Paths&) {
    return std::make_unique<NullIsolationBackend>();
}

#endif

} // namespace lexe

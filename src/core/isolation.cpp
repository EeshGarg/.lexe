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
    // GUI display variables are deliberately NOT forwarded in 0.1 (headless /
    // terminal isolation only); see the isolation docs.
    return env;
}

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
    if (req.network_allowed) {
        plan.network_shared = true;
        plan.controls[IsolationControl::NetworkDenied] =
            ControlState::NotApplicable;
        // Name resolution config only when networking is permitted.
        plan.binds.push_back({"/etc/resolv.conf", "/etc/resolv.conf", true, true});
        plan.binds.push_back({"/etc/hosts", "/etc/hosts", true, true});
    } else if (caps.network_namespaces) {
        plan.network_shared = false;
        plan.controls[IsolationControl::NetworkDenied] = ControlState::Enforced;
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
    plan.binds.push_back({app_root, app_root, true});
    plan.controls[IsolationControl::AppRootReadOnly] = ControlState::Enforced;

    // Private writable roots at fixed sandbox paths (host layout not exposed).
    plan.binds.push_back({req.data_root.generic_string(), kSandboxData, false});
    plan.binds.push_back({req.cache_root.generic_string(), kSandboxCache, false});
    plan.tmpfs = {kSandboxTemp};
    plan.controls[IsolationControl::PrivateData] = ControlState::Enforced;
    plan.controls[IsolationControl::PrivateCache] = ControlState::Enforced;
    plan.controls[IsolationControl::PrivateTemp] = ControlState::Enforced;

    // Home is never bound → not visible.
    plan.controls[IsolationControl::HomeHidden] = ControlState::Enforced;

    // Sanitized environment (allowlist) + a safe writable working directory
    // that is NOT the caller's cwd.
    plan.env = sanitize_environment(req);
    plan.working_dir = kSandboxData;
    plan.controls[IsolationControl::EnvironmentSanitized] =
        ControlState::Enforced;

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
        o.capture_stdout = false; // the app owns our stdout on a normal launch
        IsolationResult result;
        try {
            result.exit_code = util::run_process(argv, o).exit_code;
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

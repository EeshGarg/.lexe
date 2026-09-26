// session_manager — talking to `systemd --user` (session_manager.hpp,
// docs/SERVICES.md).

#include "lexe/integration/session_manager.hpp"

#include "lexe/base/error.hpp"
#include "lexe/package/crypto.hpp"
#include "lexe/base/util.hpp"
#include "lexe/integration/integration.hpp"
#include "lexe/integration/session.hpp"
#include "lexe/state/lock.hpp"
#include "lexe/state/registry.hpp"

#include <algorithm>
#include <filesystem>
#include <mutex>

namespace fs = std::filesystem;

namespace lexe::session {

const char* to_string(ManagerStatus s) {
    switch (s) {
    case ManagerStatus::Available: return "available";
    case ManagerStatus::NotInstalled: return "not-installed";
    case ManagerStatus::NoUserSession: return "no-user-session";
    case ManagerStatus::Unsupported: return "unsupported";
    }
    return "unsupported";
}

namespace {

std::string trimmed(std::string text) {
    while (!text.empty() &&
           (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
        text.pop_back();
    }
    return text;
}

/// One systemctl invocation, where a non-zero exit is an ANSWER, not a failure.
///
/// `is-enabled` exits 1 for "disabled" and `is-active` exits 3 for "inactive";
/// both are exactly what was asked for. So only a systemctl that could not be
/// STARTED is treated as a problem, and that is reported through
/// `capabilities()` rather than thrown out of a query.
struct Systemctl {
    bool started = false;
    int exit_code = -1;
    std::string out;
    std::string err;
};

Systemctl systemctl(const std::vector<std::string>& args) {
    std::vector<std::string> argv{"systemctl"};
    argv.insert(argv.end(), args.begin(), args.end());
    util::RunOptions opts;
    opts.capture_stdout = true;
    opts.capture_stderr = true;
    Systemctl result;
    try {
        const util::ProcessResult r = util::run_process(argv, opts);
        result.started = true;
        result.exit_code = r.exit_code;
        result.out = trimmed(r.stdout_text);
        result.err = trimmed(r.stderr_text);
    } catch (const std::exception& e) {
        result.err = e.what();
    }
    return result;
}

/// systemd's own words for "there is no user bus here".
///
/// Worth distinguishing from "systemd is not installed", because the remedies
/// are different: one is a missing package, the other is a session that has to
/// be logged into (or made to linger).
bool looks_like_no_bus(const std::string& stderr_text) {
    static const char* const kMarkers[] = {
        "Failed to connect to bus",
        "Failed to connect to user scope bus",
        "No medium found",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
    };
    for (const char* marker : kMarkers) {
        if (stderr_text.find(marker) != std::string::npos) return true;
    }
    return false;
}

class SystemdUserManager final : public SessionManager {
  public:
    explicit SystemdUserManager(const Paths& paths) : paths_(paths) {}

    ManagerCapabilities capabilities() const override {
        std::call_once(probed_, [this] { cached_ = probe(); });
        return cached_;
    }

    std::string enable(const Manifest& manifest, const std::string& runtime_path,
                       bool start_now) override {
        require_available();

        UnitInputs inputs;
        inputs.manifest = manifest;
        inputs.runtime_path = runtime_path;
        // Pinned only when the installation root is an override. See session.hpp:
        // an ordinary unit should follow a home directory that moves, and a test
        // suite running against a scratch root needs the unit to find that root.
        if (const std::optional<std::string> home = util::get_env("LEXE_HOME");
            home.has_value() && !home->empty()) {
            inputs.lexe_home = *home;
        }
        const std::string text = unit_text(inputs); // throws for a non-service

        const fs::path path = fs::path(unit_path(paths_, manifest.id));
        std::error_code ec;
        fs::create_directories(path.parent_path(), ec);
        // Atomic, because systemd may read this directory at any moment and a
        // unit caught half-written parses as a unit with half the directives
        // rather than as an error — `ExecStart=` present and `Restart=` not yet.
        util::write_atomic(path, std::string_view(text));

        // daemon-reload BEFORE enable, not after. `enable` reads the unit to
        // find its [Install] section, and a manager that has not reloaded reads
        // the previous content or none at all: enabling a freshly written unit
        // then fails with "No such file or directory" while the file plainly
        // exists, which is among the more confusing things systemd says.
        const Systemctl reload = systemctl({"--user", "daemon-reload"});
        if (!reload.started || reload.exit_code != 0) {
            throw Error("session: systemctl --user daemon-reload failed for " +
                            manifest.id + ": " + reload.err,
                        "The unit was written to " + path.string() +
                            " but systemd has not been told about it. Run "
                            "`systemctl --user daemon-reload` and try again.");
        }

        // Enabled by ABSOLUTE PATH, not by name, and that choice is what makes
        // this testable without a second code path.
        //
        // The unit lives under `config_home_`, which `LEXE_HOME` redirects --
        // deliberately, so a test never writes into the real user profile. But a
        // unit outside systemd's search path cannot be enabled by NAME: systemd
        // answers "Unit file lexe-<id>.service does not exist", and a suite that
        // worked around that would be exercising something other than what
        // production runs.
        //
        // `systemctl --user enable /abs/path/unit.service` handles both cases,
        // which was verified against systemd 255 rather than assumed:
        //
        //   outside the search path -> links the unit into
        //     ~/.config/systemd/user AND creates the default.target.wants
        //     symlink; it is then startable and stoppable by name
        //   inside the search path  -> creates only the wants symlink, with no
        //     redundant self-link and no complaint
        //
        // So one form covers an ordinary installation and a scratch root alike,
        // and `disable` by NAME removes what either created.
        const std::string unit = unit_name(manifest.id);
        const Systemctl enabled =
            systemctl({"--user", "enable", path.string()});
        if (!enabled.started || enabled.exit_code != 0) {
            throw Error("session: systemctl --user enable " + path.string() +
                            " failed: " + enabled.err,
                        "The unit is written and valid at " + path.string() +
                            "; systemd refused to enable it, and the message "
                            "above is systemd's own.");
        }

        record(manifest.id, path);

        if (start_now) {
            const Systemctl started = systemctl({"--user", "start", unit});
            if (!started.started || started.exit_code != 0) {
                // Enabling SUCCEEDED and is recorded; only starting failed. Say
                // exactly that: the service will still come up at next login,
                // and an error implying otherwise would send someone off to
                // re-enable what is already enabled.
                throw Error("session: " + manifest.id +
                                " is enabled, but starting it now failed: " +
                                started.err,
                            "It will start at your next login. To see why it "
                            "would not start now: `systemctl --user status " +
                                unit + "`.");
            }
        }
        return path.string();
    }

    void disable(const std::string& app_id) override {
        const std::string unit = unit_name(app_id);
        const fs::path path = fs::path(unit_path(paths_, app_id));

        // Tolerant at every step on purpose. The asked-for end state is "no
        // unit, not enabled, not running", and a stop that fails because
        // nothing was running has already achieved its part of it. The one step
        // that throws is removing the FILE, because that is the failure which
        // leaves something behind for systemd to pick up again.
        if (capabilities().status == ManagerStatus::Available) {
            systemctl({"--user", "stop", unit});
            systemctl({"--user", "disable", unit});
        }

        std::error_code ec;
        fs::remove(path, ec);
        if (fs::exists(path)) {
            throw Error("session: could not remove the unit " + path.string() +
                            (ec ? ": " + ec.message() : ""),
                        "systemd has been told to stop and disable it, but the "
                        "file is still present and will be read again at next "
                        "login.");
        }
        if (capabilities().status == ManagerStatus::Available) {
            systemctl({"--user", "daemon-reload"});
        }
        forget(app_id);
    }

    SessionState state(const std::string& app_id) const override {
        SessionState s;
        s.unit_name = unit_name(app_id);
        s.unit_path = unit_path(paths_, app_id);

        std::error_code ec;
        s.unit_present = fs::is_regular_file(fs::path(s.unit_path), ec);

        for (const IntegrationArtifact& a :
             IntegrationState::load(paths_).scope(app_id)) {
            if (a.kind == ArtifactKind::SessionUnit) s.unit_recorded = true;
        }

        const ManagerCapabilities caps = capabilities();
        if (caps.status == ManagerStatus::Available) {
            const Systemctl is_enabled =
                systemctl({"--user", "is-enabled", s.unit_name});
            s.enabled = is_enabled.out == "enabled" ||
                        is_enabled.out == "enabled-runtime";
            const Systemctl is_active =
                systemctl({"--user", "is-active", s.unit_name});
            s.active = is_active.out == "active" || is_active.out == "activating";
            s.detail = is_active.out.empty() ? is_enabled.out : is_active.out;
        } else {
            s.detail = caps.detail;
        }

        // OUTSIDE systemd specifically: when the unit is active, the lease is
        // held by the `lexe` process systemd started, and reporting that as an
        // unsupervised copy would turn the normal case into a warning.
        s.lexe_supervised_running = lease_held(app_id) && !s.active;
        return s;
    }

    void stop(const std::string& app_id) override {
        if (capabilities().status != ManagerStatus::Available) return;
        systemctl({"--user", "stop", unit_name(app_id)});
    }

  private:
    void require_available() const {
        const ManagerCapabilities caps = capabilities();
        if (caps.status == ManagerStatus::Available) return;
        throw Error("session: no user service manager is available here: " +
                        caps.detail,
                    caps.status == ManagerStatus::NotInstalled
                        ? "Install systemd, or supervise the application "
                          "yourself with `lexe run --detach`."
                        : "Log in to a session with a running user manager, or "
                          "supervise the application yourself with "
                          "`lexe run --detach`.");
    }

    ManagerCapabilities probe() const {
        ManagerCapabilities caps;
#ifdef _WIN32
        caps.status = ManagerStatus::Unsupported;
        caps.detail = "Windows has no systemd user session; .LEXE supervises "
                      "detached applications itself here.";
        return caps;
#else
        const Systemctl version = systemctl({"--version"});
        if (!version.started) {
            caps.status = ManagerStatus::NotInstalled;
            caps.detail = "systemctl is not on PATH";
            return caps;
        }
        // "systemd 255 (255.4-1ubuntu8...)" — the first line is the version.
        const std::size_t eol = version.out.find('\n');
        caps.manager_version =
            eol == std::string::npos ? version.out : version.out.substr(0, eol);

        // --version answers without a bus, so it proves systemd is INSTALLED
        // and nothing more. This is the question that needs the bus, asked with
        // a command that changes nothing.
        const Systemctl running = systemctl({"--user", "is-system-running"});
        if (!running.started || looks_like_no_bus(running.err)) {
            caps.status = ManagerStatus::NoUserSession;
            caps.detail =
                running.err.empty()
                    ? "systemctl --user could not reach a user session manager"
                    : running.err;
            return caps;
        }
        // A NON-ZERO exit is fine here and must not be read as unavailable:
        // `is-system-running` reports "degraded" with status 1 whenever any
        // unit in the session has ever failed, which says nothing about whether
        // the manager can be talked to. It answered; that was the question.
        caps.status = ManagerStatus::Available;
        caps.detail = "systemd user session: " +
                      (running.out.empty() ? std::string("responding")
                                           : running.out);
        return caps;
#endif
    }

    /// Whether ANY process holds the current version's launch lease.
    ///
    /// The only liveness signal the runtime has — there is no pid file. Probed
    /// by trying to take the lease exclusively and dropping it again at once: an
    /// exclusive attempt fails exactly when someone holds it shared, and the
    /// attempt is non-blocking, so a status query never waits on a running
    /// application.
    bool lease_held(const std::string& app_id) const {
        try {
            const Registry registry(paths_);
            if (!registry.is_installed(app_id)) return false;
            const std::string version = registry.current_version(app_id);
            const std::unique_ptr<OperationLockManager> locks =
                make_lock_manager(paths_);
            return !locks->try_lock_version_for_gc(app_id, version).has_value();
        } catch (const std::exception&) {
            // A liveness probe must never be the thing that fails a status
            // report. Unknown reads as "not detected", and everything else in
            // the state is still worth showing.
            return false;
        }
    }

    /// Record the unit alongside the other durable integration artifacts, so
    /// `lexe doctor` can name it and uninstall knows to remove it.
    void record(const std::string& app_id, const fs::path& path) const {
        IntegrationState state = IntegrationState::load(paths_);
        std::vector<IntegrationArtifact> scope = without_unit(state, app_id);
        IntegrationArtifact artifact;
        artifact.kind = ArtifactKind::SessionUnit;
        artifact.path = path.string();
        artifact.sha256 = crypto::sha256_file_hex(path);
        artifact.owner_app = app_id;
        scope.push_back(artifact);
        state.replace_scope(app_id, scope);
        state.save(paths_);
    }

    void forget(const std::string& app_id) const {
        IntegrationState state = IntegrationState::load(paths_);
        std::vector<IntegrationArtifact> scope = state.scope(app_id);
        const std::size_t before = scope.size();
        scope = without_unit(state, app_id);
        if (scope.size() == before) return;
        state.replace_scope(app_id, scope);
        state.save(paths_);
    }

    /// This application's artifacts with any recorded unit removed. Every write
    /// here goes through replace_scope, which rewrites the whole scope, so an
    /// artifact omitted from the vector is DE-REGISTERED — the rest must be
    /// carried forward deliberately, exactly as install_app carries icons.
    static std::vector<IntegrationArtifact>
    without_unit(const IntegrationState& state, const std::string& app_id) {
        std::vector<IntegrationArtifact> scope = state.scope(app_id);
        scope.erase(std::remove_if(scope.begin(), scope.end(),
                                   [](const IntegrationArtifact& a) {
                                       return a.kind == ArtifactKind::SessionUnit;
                                   }),
                    scope.end());
        return scope;
    }

    Paths paths_;
    mutable std::once_flag probed_;
    mutable ManagerCapabilities cached_;
};

} // namespace

std::unique_ptr<SessionManager> make_session_manager(const Paths& paths) {
    return std::make_unique<SystemdUserManager>(paths);
}

} // namespace lexe::session

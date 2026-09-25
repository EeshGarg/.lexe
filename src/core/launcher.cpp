// launcher — see launcher.hpp. The POST-INSTALL / RUN role of the Definitive
// Architecture (§7, §14.4, §15, §16).
//
// Security invariants preserved from the alpha implementation and never
// relaxed: nothing outside the app's current version directory is executed
// (invariant #6, checked on the CANONICAL resolved path), the child is spawned
// as an argv array and never through a shell (invariant #3), the entrypoint's
// integrity is revalidated against the hash recorded at install, and isolation
// fails CLOSED — a backend that should work but does not never degrades to an
// unconfined launch.

#include "core/launcher.hpp"

#include "core/appconfig.hpp"
#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/hostbuild.hpp"
#include "core/isolation.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/lock.hpp"
#include "core/manifest.hpp"
#include "core/permissions.hpp"
#include "core/registry.hpp"
#include "core/trust.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"
#include "core/version.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <system_error>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace lexe {

namespace {

/// True when canonical path `p` is strictly inside canonical directory
/// `root` (equal to `root` itself does not count — the entrypoint must be a
/// file within the directory).
bool strictly_inside(const fs::path& root, const fs::path& p) {
    const fs::path rel = p.lexically_relative(root);
    if (rel.empty() || rel == ".") return false;      // unrelated / same path
    return rel.begin()->string() != "..";             // must not walk up
}

/// The caller's environment, as a map, so isolation policy can decide what (if
/// anything) to forward. Reading it here keeps isolation's pure functions pure.
std::map<std::string, std::string> caller_environment() {
    std::map<std::string, std::string> env;
    for (const char* name :
         {"WAYLAND_DISPLAY", "DISPLAY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
          "XDG_CURRENT_DESKTOP", "GDK_BACKEND", "QT_QPA_PLATFORM", "LANG",
          "LC_ALL", "LC_MESSAGES"}) {
        if (const std::optional<std::string> value = util::get_env(name)) {
            if (!value->empty()) env[name] = *value;
        }
    }
    return env;
}

/// Is our stdout a terminal? Decides whether a console application already has
/// somewhere to print (§14.4).
bool stdout_is_terminal() {
#ifdef _WIN32
    return true;
#else
    return ::isatty(STDOUT_FILENO) == 1;
#endif
}

/// A truthful one-line summary of what the sandbox actually enforced.
std::string summarize_controls(
    const std::map<IsolationControl, ControlState>& controls) {
    std::vector<std::string> enforced;
    std::vector<std::string> not_enforced;
    for (const auto& [control, state] : controls) {
        if (state == ControlState::Enforced) {
            enforced.push_back(to_string(control));
        } else if (state != ControlState::NotApplicable) {
            not_enforced.push_back(to_string(control) + "=" + to_string(state));
        }
    }
    std::string summary = "enforced: " + std::to_string(enforced.size());
    if (!not_enforced.empty()) {
        summary += " (not enforced: ";
        for (std::size_t i = 0; i < not_enforced.size(); ++i) {
            if (i != 0) summary += ", ";
            summary += not_enforced[i];
        }
        summary += ")";
    }
    return summary;
}

/// Build the base of an error record from what we know so far, so every throw
/// site records the same structured shape (§9).
/// The launcher fills the same five fields on every gate; the rest of the
/// record (runtime version, host OS/ISA) is machine truth the shared helper
/// supplies. `fail_with_record` lives beside it in core/diagnostics.hpp so
/// install-time gates pair a typed failure with a record the same way.
ErrorRecord base_record(const std::string& id, const std::string& version,
                        FailureStage stage, const std::string& summary,
                        const std::string& detail) {
    return make_error_record(id, version, stage, summary, detail);
}

/// Terminal emulators .LEXE will use for a console application, in preference
/// order. Each entry is {executable, flag that introduces the command}.
struct TerminalSpec {
    const char* executable;
    const char* exec_flag;
};
constexpr TerminalSpec kTerminals[] = {
    {"konsole", "-e"},        {"ptyxis", "--"},
    {"gnome-terminal", "--"}, {"xfce4-terminal", "-x"},
    {"alacritty", "-e"},      {"kitty", "-e"},
    {"foot", "-e"},           {"xterm", "-e"},
};

std::string which_executable(const std::string& name) {
    const std::optional<std::string> path_env = util::get_env("PATH");
    if (!path_env.has_value()) return {};
    std::size_t start = 0;
    while (start <= path_env->size()) {
        const std::size_t sep = path_env->find(':', start);
        const std::string dir = path_env->substr(
            start, sep == std::string::npos ? std::string::npos : sep - start);
        if (!dir.empty()) {
            const fs::path candidate = fs::path(dir) / name;
            std::error_code ec;
            if (fs::is_regular_file(candidate, ec)) {
                const fs::perms perms = fs::status(candidate, ec).permissions();
                if (!ec && (perms & fs::perms::owner_exec) != fs::perms::none) {
                    return candidate.string();
                }
            }
        }
        if (sep == std::string::npos) break;
        start = sep + 1;
    }
    return {};
}

} // namespace

std::string detect_terminal_emulator() {
    for (const TerminalSpec& spec : kTerminals) {
        const std::string path = which_executable(spec.executable);
        if (!path.empty()) return path;
    }
    return {};
}

namespace {

/// The argv that re-invokes `lexe run <id>` inside a terminal emulator.
/// Returns an empty vector when no terminal is available on this host.
std::vector<std::string> terminal_argv(const std::string& id,
                                       const std::vector<std::string>& args) {
    for (const TerminalSpec& spec : kTerminals) {
        const std::string terminal = which_executable(spec.executable);
        if (terminal.empty()) continue;
        std::vector<std::string> argv = {terminal, spec.exec_flag};
        // Re-enter through the .LEXE runtime, never through the payload: the
        // terminal launches `lexe run`, so every gate runs exactly once more
        // and the application is still executed by .LEXE (§14.6).
        argv.push_back(which_executable("lexe").empty()
                           ? std::string("lexe")
                           : which_executable("lexe"));
        argv.push_back("run");
        argv.push_back(id);
        argv.push_back("--attached-terminal");
        if (!args.empty()) {
            argv.push_back("--");
            argv.insert(argv.end(), args.begin(), args.end());
        }
        return argv;
    }
    return {};
}

/// Everything resolved before a launch, shared by run_application() and
/// resolve_application_chain().
struct ResolvedApplication {
    InstallationRecord record;
    Manifest manifest;
    std::string version;
    fs::path version_dir;
    AppConfig config;
};

ResolvedApplication resolve_installed(const Paths& paths,
                                      const std::string& id) {
    const Registry registry(paths);
    ResolvedApplication resolved;
    resolved.record = registry.read_record(id); // throws NotFoundError
    resolved.version = registry.current_version(id);
    resolved.version_dir = registry.version_dir(id, resolved.version);
    resolved.manifest = registry.read_manifest(id);
    resolved.config = AppConfig::load(paths, id);
    return resolved;
}

} // namespace

ChainResolution resolve_application_chain(const Paths& paths,
                                          const std::string& id) {
    const ResolvedApplication app = resolve_installed(paths, id);
    return resolve_chain(app.manifest, app.config, detect_host(),
                         probe_providers());
}

ExecutionReport run_application(const Paths& paths, const RunRequest& request) {
    const std::string& id = request.id;
    const Registry registry(paths);
    ExecutionReport report;
    report.id = id;

    // Throws NotFoundError when the app is not installed.
    InstallationRecord record = registry.read_record(id);

    // Enforce LOCAL trust before doing anything else. A locally blocked App ID
    // must not launch; a corrupt trust record, or one that binds a DIFFERENT
    // key than the installed (pinned) key, fails closed. The launcher never
    // falls through to executing a refused application.
    {
        crypto::PublicKey installed_key;
        try {
            installed_key = crypto::decode_public_key(record.publisher_key);
        } catch (const Error&) {
            fail_with_record<LaunchError>(
                paths,
                base_record(id, record.version, FailureStage::Verification,
                            "the installed publisher key is unreadable",
                            "installation.json records a publisher key that "
                            "cannot be decoded; the launch is refused rather "
                            "than executed without a trust anchor"),
                "launcher: installed publisher key for " + id +
                    " is unreadable; refusing to launch");
        }
        const TrustEvaluation eval = TrustStore(paths).evaluate(
            id, installed_key, SignatureState::Valid, std::nullopt);
        try {
            eval.throw_if_rejected(); // no-op when allowed
        } catch (const Error& e) {
            // Record the diagnostic, then RE-THROW THE ORIGINAL exception.
            // The trust hierarchy is typed on purpose (BlockedKeyError,
            // ChangedKeyError, CorruptTrustError, …) and frontends switch on
            // those types — collapsing them into the base class to attach a
            // record would destroy information the architecture depends on.
            (void)ErrorStore(paths).record(base_record(
                id, record.version, FailureStage::Verification,
                "local trust refuses this application", e.what()));
            throw;
        }
    }

    // Active version (symlink or current.txt fallback). version_dir()
    // re-validates the version string, so a tampered current pointer can never
    // traverse outside apps/<id>/versions/.
    const std::string version = registry.current_version(id);
    const fs::path version_dir = registry.version_dir(id, version);
    report.version = version;

    // TOCTOU closure around the launch: take a SHARED launch lease on THIS
    // (id, version) and hold it for the entire run. From here on every check
    // and the exec use the IMMUTABLE versions/<version> path — `current` is
    // never re-read — so a concurrent update that flips `current` cannot make
    // us run a torn mix, and the lease keeps the version's files on disk even
    // after it is superseded. The lock fd is O_CLOEXEC, so the sandboxed child
    // never inherits or observes it.
    const std::unique_ptr<OperationLockManager> locks = make_lock_manager(paths);
    const LaunchLease lease = locks->acquire_launch_lease(
        id, version, WaitPolicy::bounded(std::chrono::seconds(5)));

    std::error_code ec;
    // Revalidate AFTER leasing: if a concurrent remove/GC won the tiny race
    // between resolving the version and leasing it, fail closed rather than
    // execute a half-removed version.
    if (!fs::is_directory(version_dir, ec)) {
        fail_with_record<Error>(
            paths,
            base_record(id, version, FailureStage::Launch,
                        "the active version directory is missing",
                        "the current version of " + id +
                            " was removed while the launch was starting: " +
                            version_dir.string()),
            "launcher: current version directory of " + id +
                " is missing: " + version_dir.string());
    }

    // The manifest.json copy of the active version; Manifest::parse re-checks
    // every FORMAT-0.1 §5 constraint even if the copy was tampered with.
    const Manifest manifest = registry.read_manifest(id);
    report.launch_mode = to_string(manifest.launch_mode);
    report.mission_critical = manifest.mission_critical;

    // ---------------------------------------------- READ EXECUTION POLICY
    // §6/§8. The chain is resolved from three independent inputs: the signed
    // package policy, this user's overrides, and what is actually installed
    // here. A mission-critical application resolves through the STRICT
    // resolver, which offers no fallback and no "run anyway".
    AppConfig config = AppConfig::load(paths, id);
    if (request.chain_override.has_value()) {
        // A power-user override is expressed as a manual preference, so it goes
        // through exactly the same policy filter as a stored one (§8: only
        // chains allowed by the package policy are ever honoured).
        config.compatibility_mode = CompatibilityMode::Manual;
        config.preferred_chain = {*request.chain_override};
    }
    const ProviderSet providers = probe_providers();
    const ChainResolution resolution =
        resolve_chain(manifest, config, detect_host(), providers);
    if (!resolution.ok) {
        ErrorRecord failure = base_record(
            id, version,
            manifest.mission_critical ? FailureStage::ExecutionPolicy
                                      : FailureStage::ChainResolution,
            manifest.mission_critical
                ? "mission-critical policy stops execution"
                : "no permitted execution chain is available",
            resolution.reason);
        failure.launch_mode = to_string(manifest.launch_mode);
        for (const RejectedChain& rejected : resolution.rejected) {
            failure.detail +=
                "\n  - " + rejected.id + ": " + rejected.reason;
        }
        fail_with_record<LaunchError>(paths, std::move(failure),
                                      "launcher: " + resolution.reason);
    }
    if (request.chain_override.has_value() &&
        resolution.chain.id != *request.chain_override) {
        // Be explicit rather than silently running something else.
        throw LaunchError(
            "launcher: execution chain \"" + *request.chain_override +
            "\" is not available for " + id +
            " under this package's execution policy; .LEXE would use \"" +
            resolution.chain.id + "\" instead. Run `lexe compat " + id +
            "` to see the chains this package allows.");
    }
    report.chain = resolution.chain.id;
    report.chain_reason = resolution.reason;

    // ------------------------------------------------- RUNTIME RESOLUTION
    // §16: the expensive dependency analysis happened at install/repair. A
    // normal native launch only CONFIRMS the recorded state still holds, then
    // execs — no compatibility layer required means no performance tax.
    if (!record.runtime_unresolved.empty()) {
        ErrorRecord failure = base_record(
            id, version, FailureStage::RuntimeResolution,
            "the application's dependency contract is not satisfied",
            "these libraries could not be resolved when " + id +
                " was installed, so the dynamic loader would fail at exec:");
        for (const std::string& soname : record.runtime_unresolved) {
            failure.detail += "\n  - " + soname;
        }
        failure.detail +=
            "\n\nRun `lexe repair " + id +
            "` to re-resolve the runtime contract after installing what is "
            "missing.";
        failure.execution_chain = resolution.chain.id;
        failure.launch_mode = to_string(manifest.launch_mode);
        failure.runtime_profile = record.runtime_source;
        fail_with_record<LaunchError>(
            paths, std::move(failure),
            "launcher: " + id +
                " cannot start: its dependency contract is not satisfied on "
                "this host");
    }

    // Resolve the entrypoint and reject any resolution that escapes the
    // version directory (security invariant #6). weakly_canonical follows
    // symlinks in the existing part of the path, so a symlinked subdirectory
    // pointing elsewhere is caught here as well.
    const fs::path root = fs::weakly_canonical(version_dir, ec);
    if (ec) {
        throw Error("launcher: cannot resolve version directory: " +
                    version_dir.string());
    }
    const fs::path entry = fs::weakly_canonical(
        version_dir / fs::path(manifest.entrypoint_executable), ec);
    if (ec || !strictly_inside(root, entry)) {
        throw Error("launcher: entrypoint \"" +
                    manifest.entrypoint_executable +
                    "\" resolves outside the current version directory of " +
                    id);
    }
    if (!fs::is_regular_file(entry, ec)) {
        fail_with_record<Error>(
            paths,
            base_record(id, version, FailureStage::Launch,
                        "the application's entrypoint is missing",
                        "the installed payload no longer contains \"" +
                            manifest.entrypoint_executable +
                            "\". Run `lexe repair " + id + "`."),
            "launcher: entrypoint missing for " + id + ": " + entry.string());
    }

    // Revalidate the entrypoint's integrity against the hash recorded at
    // install time, so a binary tampered with AFTER installation is never
    // executed. Enforced whenever a recorded hash for the entrypoint is
    // present (every real install writes one); the launch is refused on
    // mismatch — it never falls through to direct execution.
    {
        const std::string key = "payload/" + manifest.entrypoint_executable;
        std::string expected;

        // A portable application's entrypoint was COMPILED here, so it is not
        // in the package's signed hashes — it did not exist when the package
        // was signed. Its hash was recorded at build time instead. Consulting
        // only hashes.json would find nothing for exactly those entrypoints
        // and skip the check, leaving compiled binaries the one kind this
        // runtime never noticed being replaced.
        const std::optional<BuildRecord> build_record =
            BuildRecord::load(registry.meta_dir(id, version));
        if (build_record.has_value()) {
            const auto product = build_record->products.find(key);
            if (product != build_record->products.end()) {
                expected = product->second;
            }
        }

        fs::path hashes_file = registry.meta_dir(id, version) / "hashes.json";
        if (!fs::is_regular_file(hashes_file, ec)) {
            hashes_file = registry.app_dir(id) / "hashes.json";
        }
        if (expected.empty() && fs::is_regular_file(hashes_file, ec)) {
            const nlohmann::json doc =
                json_strict::parse(util::slurp_text(hashes_file),
                                   "installed hashes.json", limits::kMaxHashesBytes);
            const auto files = doc.find("files");
            if (files != doc.end() && files->is_object()) {
                const auto it = files->find(key);
                if (it != files->end() && it->is_string()) {
                    expected = it->get<std::string>();
                }
            }
        }

        // Fail CLOSED for a portable application with no recorded product
        // hash: that means the build record is gone, and an unverifiable
        // compiled binary is not one to run.
        if (expected.empty() &&
            manifest.application_kind == ApplicationType::Portable) {
            fail_with_record<LaunchError>(
                paths,
                base_record(id, version, FailureStage::Verification,
                            "there is no record of what this application was "
                            "built from",
                            "the entrypoint of " + id +
                                " is compiled on this machine, and the build "
                                "record that says what it should hash to is "
                                "missing — so its integrity cannot be "
                                "checked. Run `lexe repair " + id +
                                " --approve-compile` to build it again."),
                "launcher: no build record for portable application " + id +
                    "; refusing to launch an unverifiable compiled entrypoint.");
        }

        if (!expected.empty() && crypto::sha256_file_hex(entry) != expected) {
            const std::string remedy =
                manifest.application_kind == ApplicationType::Portable
                    ? "Run `lexe repair " + id + " --approve-compile`."
                    : "Run `lexe repair " + id + "`.";
            fail_with_record<LaunchError>(
                paths,
                base_record(id, version, FailureStage::Verification,
                            "the installed executable failed its integrity "
                            "check",
                            "the entrypoint of " + id +
                                " does not match the hash recorded when it was "
                                "installed — it was modified after "
                                "installation. " + remedy),
                "launcher: entrypoint of " + id +
                    " fails its recorded integrity check (modified after "
                    "install); refusing to launch. " + remedy);
        }
    }

#ifndef _WIN32
    // Ensure the entrypoint is executable (ZIP extraction does not always
    // preserve mode bits). Exec is added for owner, and for group/others
    // where the corresponding read bit is already present.
    const fs::perms perms = fs::status(entry, ec).permissions();
    if (ec) {
        throw Error("launcher: cannot stat entrypoint: " + entry.string());
    }
    if ((perms & fs::perms::owner_exec) == fs::perms::none) {
        fs::perms add = fs::perms::owner_exec;
        if ((perms & fs::perms::group_read) != fs::perms::none) {
            add |= fs::perms::group_exec;
        }
        if ((perms & fs::perms::others_read) != fs::perms::none) {
            add |= fs::perms::others_exec;
        }
        fs::permissions(entry, add, fs::perm_options::add, ec);
        if (ec) {
            throw Error("launcher: entrypoint of " + id +
                        " is not executable and the exec bit cannot be set: " +
                        entry.string());
        }
    }
#endif

    // ------------------------------------------------- LAUNCH PRESENTATION
    // §14.4: presentation is DECLARED. A console application launched with no
    // terminal is given one by .LEXE — the desktop is never asked to infer it.
    if (manifest.launch_mode == LaunchMode::Console && !request.attached_terminal &&
        !stdout_is_terminal() && request.allow_terminal_spawn) {
        const std::vector<std::string> argv = terminal_argv(id, request.args);
        if (!argv.empty()) {
            util::RunOptions options;
            options.capture_stdout = false;
            const util::ProcessResult terminal = util::run_process(argv, options);
            report.started = true;
            report.exit_code = terminal.exit_code;
            record.last_run_at = util::now_utc_string();
            record.last_exit_code = terminal.exit_code;
            record.last_chain = resolution.chain.id;
            record.last_launch_mode = to_string(manifest.launch_mode);
            registry.write_record(record);
            return report;
        }
        // No terminal emulator on this host: fall through and CAPTURE the
        // output into the diagnostic store instead, so a console application
        // still cannot "look like nothing happened".
    }

    // App arguments (manifest arguments then caller arguments) — argv elements
    // end to end, never a shell (security invariant #3).
    std::vector<std::string> app_args;
    app_args.reserve(manifest.entrypoint_arguments.size() + request.args.size());
    app_args.insert(app_args.end(), manifest.entrypoint_arguments.begin(),
                    manifest.entrypoint_arguments.end());
    app_args.insert(app_args.end(), request.args.begin(), request.args.end());

    // ----------------------------------------------------- SANDBOX / PREPARE
    const NormalizedPermissions approved =
        normalized_from_ids(record.approved_permissions);
    const bool network_allowed =
        std::find(approved.ids.begin(), approved.ids.end(),
                  std::string("network")) != approved.ids.end();

    const fs::path data_root = registry.app_data_dir(id);
    const fs::path cache_root = registry.app_cache_dir(id);
    std::error_code mkec;
    fs::create_directories(data_root, mkec);
    fs::create_directories(cache_root, mkec);

    IsolationRequest req;
    req.app_id = id;
    req.app_root = root;
    req.entrypoint = entry;
    req.args = app_args;
    req.data_root = data_root;
    req.cache_root = cache_root;
    req.network_allowed = network_allowed;
    // §14.4: the DECLARED launch mode decides display access — never a guess
    // about whether a window might appear.
    req.gui = manifest.launch_mode == LaunchMode::Gui;
    // A compatibility layer has to be reachable inside the sandbox or the
    // chain that was just resolved cannot run. Empty for native, which is why
    // the native steady state has nothing extra bound into it either.
    req.compatibility_paths = resolution.chain.argv_prefix;
    req.private_runtime_dir = sandbox_runtime_dir_for_current_user();
    req.inherited_env = caller_environment();

    const std::unique_ptr<IsolationBackend> backend =
        make_isolation_backend(paths);
    const IsolationCapabilities caps = backend->capabilities();

    // A console application with nowhere to print gets its output captured so
    // it can be shown afterwards; everything else owns our streams directly.
    const bool capture_output =
        manifest.launch_mode == LaunchMode::Console && !stdout_is_terminal();

    int exit_code = 0;
    std::optional<int> signal;
    std::string captured_stdout;
    std::string captured_stderr;
    std::map<IsolationControl, ControlState> enforced;

    try {
        if (caps.status == CapabilityStatus::PolicyUnsupported) {
            // No isolation backend on this platform (e.g. a Windows dev host):
            // run directly. This is NOT a fail-closed failure — the platform
            // has no isolation to establish; the capability is reported
            // truthfully rather than claimed.
            std::vector<std::string> argv = resolution.chain.argv_prefix;
            argv.push_back(entry.string());
            argv.insert(argv.end(), app_args.begin(), app_args.end());
            util::RunOptions options;
            options.cwd = root;
            options.capture_stdout = capture_output;
            options.capture_stderr = capture_output;
            const util::ProcessResult result = util::run_process(argv, options);
            exit_code = result.exit_code;
            signal = result.signal;
            captured_stdout = result.stdout_text;
            captured_stderr = result.stderr_text;
        } else if (caps.status == CapabilityStatus::Unavailable ||
                   caps.status == CapabilityStatus::SetupFailed) {
            // Isolation is expected here but the backend does not work — FAIL
            // CLOSED. Never execute the application unconfined.
            throw IsolationError(
                "launcher: runtime isolation backend is unavailable (" +
                caps.detail + "); refusing to launch " + id + " unconfined");
        } else {
            IsolationPlan plan = build_plan(req, caps);
            // §8: the execution chain contributes an argv PREFIX. The native
            // chain contributes nothing at all, so the steady-state native path
            // has no extra process in it (§17 acceptance criterion).
            if (!resolution.chain.argv_prefix.empty()) {
                std::vector<std::string> argv = resolution.chain.argv_prefix;
                argv.insert(argv.end(), plan.app_argv.begin(),
                            plan.app_argv.end());
                plan.app_argv = std::move(argv);
            }
            plan.capture_output = capture_output;
            const IsolationResult result = backend->run(plan);
            exit_code = result.exit_code;
            signal = result.signal;
            captured_stdout = result.stdout_text;
            captured_stderr = result.stderr_text;
            enforced = result.enforced;
        }
    } catch (const IsolationError& e) {
        ErrorRecord failure =
            base_record(id, version, FailureStage::Isolation,
                        "the application sandbox could not be established",
                        e.what());
        failure.execution_chain = resolution.chain.id;
        failure.launch_mode = to_string(manifest.launch_mode);
        fail_with_record<IsolationError>(paths, std::move(failure), e.what());
    }

    report.started = true;
    report.exit_code = exit_code;
    report.signal = signal;
    report.isolation_summary = summarize_controls(enforced);

    // ------------------------------------------------ record execution report
    record.last_run_at = util::now_utc_string();
    record.last_exit_code = exit_code;
    record.last_chain = resolution.chain.id;
    record.last_launch_mode = to_string(manifest.launch_mode);
    registry.write_record(record);

    // §14.4: exit code 0 is SUCCESS even when no window appeared. Only a
    // non-zero exit or a signal produces a .lexe-error record.
    if (exit_code != 0 || signal.has_value()) {
        ErrorRecord failure = base_record(
            id, version, FailureStage::Runtime,
            signal.has_value()
                ? "the application was terminated by a signal"
                : "the application exited with an error",
            signal.has_value()
                ? "the application was killed by signal " +
                      std::to_string(*signal) + " while running under the \"" +
                      resolution.chain.id + "\" execution chain"
                : "the application ran and exited with code " +
                      std::to_string(exit_code) + " under the \"" +
                      resolution.chain.id + "\" execution chain");
        failure.execution_chain = resolution.chain.id;
        failure.launch_mode = to_string(manifest.launch_mode);
        failure.runtime_profile = record.runtime_source;
        failure.exit_code = exit_code;
        failure.signal = signal;
        report.error = ErrorStore(paths).record(std::move(failure),
                                                captured_stdout,
                                                captured_stderr);
    } else if (capture_output && !captured_stdout.empty()) {
        // A console application that succeeded but had nowhere to print: show
        // the user its output rather than leaving "nothing happened".
        std::fputs(captured_stdout.c_str(), stdout);
    }

    return report;
}

int run_app(const Paths& paths, const std::string& id,
            const std::vector<std::string>& args) {
    RunRequest request;
    request.id = id;
    request.args = args;
    return run_application(paths, request).exit_code;
}

} // namespace lexe

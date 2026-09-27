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

#include "lexe/runtime/launcher.hpp"

#include "lexe/state/appconfig.hpp"
#include "lexe/package/crypto.hpp"
#include "lexe/base/error.hpp"
#include "lexe/runtime/hostbuild.hpp"
#include "lexe/sandbox/isolation.hpp"
#include "lexe/base/json_strict.hpp"
#include "lexe/base/limits.hpp"
#include "lexe/state/lock.hpp"
#include "lexe/package/manifest.hpp"
#include "lexe/sandbox/permissions.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/verify/trust.hpp"
#include "lexe/base/util.hpp"
#include "lexe/verify/verify.hpp"
#include "lexe/base/version.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <system_error>

#ifndef _WIN32
#include <langinfo.h>
#include <locale.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace lexe {

// The retained diagnostic copy must fit inside what the error store keeps, with
// room for the note appended to it, or the store truncates a second time and
// reports a count that means nothing about the program. See
// limits::kMaxRetainedOutputBytes.
static_assert(limits::kMaxRetainedOutputBytes + 1024 <=
                  ErrorStore::kMaxStreamBytes,
              "the retained output sample must fit in an error record, leaving "
              "room for the note, so only ONE layer ever truncates");

namespace {

/// True when canonical path `p` is strictly inside canonical directory
/// `root` (equal to `root` itself does not count — the entrypoint must be a
/// file within the directory).
bool strictly_inside(const fs::path& root, const fs::path& p) {
    const fs::path rel = p.lexically_relative(root);
    if (rel.empty() || rel == ".") return false;      // unrelated / same path
    return rel.begin()->string() != "..";             // must not walk up
}

/// Can this locale name actually carry UTF-8 text on THIS host?
///
/// Two questions, and a value that fails either is worse than no value at all,
/// because a present-but-useless value suppresses the fallback:
///
///   * **Does it resolve?** A name the host has no locale data for degrades
///     silently to C, which is ASCII. `en_US.UTF-8` is the commonest desktop
///     locale in the world and is *not* generated on minimal, container or WSL
///     images — the host this was measured on has exactly three locales: `C`,
///     `C.utf8`, `POSIX`.
///   * **Is its codeset UTF-8?** A legacy 8-bit locale resolves perfectly well
///     and still cannot represent the entry paths a `.lexe` carries, which
///     §2.1 of the format requires to be UTF-8.
///
/// Measured, after the launcher started forwarding locale at all: with the
/// caller's `LANG=en_US.UTF-8` on this host, a package's `café` argument reached
/// the application as `caf\x43\x29` — the high bit stripped from every
/// non-ASCII byte. That is exactly the corruption forwarding the locale was
/// meant to FIX, reintroduced by trusting the value.
///
/// Which is the lesson worth keeping: `LANG` is not a preference the caller is
/// entitled to have honoured. It is a claim about what the host supports, and
/// it can be false. Every other variable in this function is forwarded because
/// the caller said so; this one has to be checked.
bool locale_handles_utf8(const std::string& name) {
#ifdef _WIN32
    (void)name;
    return true;
#else
    if (name.empty()) return false;
    // newlocale rather than setlocale: it answers the question without touching
    // this process's global locale, which the rest of the runtime depends on.
    const ::locale_t loc = ::newlocale(LC_CTYPE_MASK, name.c_str(), nullptr);
    if (loc == nullptr) return false; // no locale data for it on this host
    const char* codeset = ::nl_langinfo_l(CODESET, loc);
    std::string cs = codeset == nullptr ? std::string() : codeset;
    ::freelocale(loc);
    for (char& c : cs) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return cs == "UTF-8" || cs == "UTF8";
#endif
}

/// The caller's environment, as a map, so isolation policy can decide what (if
/// anything) to forward. Reading it here keeps isolation's pure functions pure —
/// including the locale check above, which is a host query and would not belong
/// in the plan builder.
std::map<std::string, std::string> caller_environment() {
    std::map<std::string, std::string> env;
    for (const char* name :
         {"WAYLAND_DISPLAY", "DISPLAY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
          "XDG_CURRENT_DESKTOP", "GDK_BACKEND", "QT_QPA_PLATFORM"}) {
        if (const std::optional<std::string> value = util::get_env(name)) {
            if (!value->empty()) env[name] = *value;
        }
    }
    // Locale is forwarded only when it is USABLE here. Dropping an unusable one
    // is what lets the sandbox's C.UTF-8 fallback apply — with the bad value
    // present, the fallback never fired and the application got ASCII.
    //
    // LC_MESSAGES is held to the same rule. It only selects message
    // translations, so its codeset matters less, but a name the host cannot
    // resolve is useless for that too, and one rule is easier to keep true than
    // two.
    for (const char* name : {"LANG", "LC_ALL", "LC_MESSAGES"}) {
        const std::optional<std::string> value = util::get_env(name);
        if (!value.has_value() || value->empty()) continue;
        if (locale_handles_utf8(*value)) env[name] = *value;
    }
    return env;
}

/// Is there a display a terminal emulator could actually map a window on?
///
/// Gate on this before hunting for one. A terminal emulator with nowhere to draw
/// cannot give a console application a terminal, so on a headless host — a CI
/// job, a cron entry, a container, an ssh session without forwarding — the search
/// can only ever fail, and the launch falls through to capture-and-relay either
/// way. The answer is the same and the work is not: see which_executable for why
/// that search is expensive, and note that the scripted invocation which pays
/// most for it is exactly the one that can never use the result.
bool display_available() {
    for (const char* name : {"WAYLAND_DISPLAY", "DISPLAY"}) {
        if (const std::optional<std::string> value = util::get_env(name)) {
            if (!value->empty()) return true;
        }
    }
    return false;
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

/// Find `name` on PATH.
///
/// `skip_foreign_mounts` drops PATH entries under `/mnt/`, which is where a
/// Linux host mounts a foreign OS's filesystem. It exists for a measured
/// reason. On a WSL host the inherited PATH carries the whole Windows PATH —
/// around fifty directories on a 9p/DrvFS mount where a single failed stat costs
/// about 10 ms — so a lookup that misses walks all of them. Searching for ten
/// terminal emulators across that PATH was measured at **1634 ms in 511
/// `newfstatat` calls**, which was the entire cost of a captured console launch:
/// 1.3 s against 38 ms for every launch mode that does not look for a terminal.
///
/// Nothing was wrong with the search except where it was looking. A Windows
/// executable cannot host a Linux console application, so those directories can
/// never contain an answer, and the cost bought nothing. Left off for ordinary
/// lookups, where PATH means what the caller says it means.
std::string which_executable(const std::string& name,
                             bool skip_foreign_mounts = false) {
    const std::optional<std::string> path_env = util::get_env("PATH");
    if (!path_env.has_value()) return {};
    std::size_t start = 0;
    while (start <= path_env->size()) {
        const std::size_t sep = path_env->find(':', start);
        const std::string dir = path_env->substr(
            start, sep == std::string::npos ? std::string::npos : sep - start);
        if (skip_foreign_mounts && dir.rfind("/mnt/", 0) == 0) {
            if (sep == std::string::npos) break;
            start = sep + 1;
            continue;
        }
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
        const std::string terminal =
            which_executable(spec.executable, /*skip_foreign_mounts=*/true);
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
    // Probe compatibility runtimes only when the launch might actually use one.
    //
    // See native_launch_is_certain: a native launch cannot use Proton, FEX,
    // Box64 or qemu, and probing for them searched every `PATH` directory for
    // each of the four. That was 1.4 of the 1.8 seconds a launch took on this
    // host, spent entirely on stats that could not change the outcome.
    //
    // An empty set is safe for the native case precisely because
    // `chain_available` returns true for a native chain without consulting
    // providers at all. Every other case takes the full probe, so the cost is
    // paid where it buys something.
    const HostFacts host = detect_host();
    const ProviderSet providers = native_launch_is_certain(manifest, config, host)
                                      ? ProviderSet{}
                                      : probe_providers();
    const ChainResolution resolution =
        resolve_chain(manifest, config, host, providers);
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
        !stdout_is_terminal() && request.allow_terminal_spawn &&
        display_available()) {
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
    // Environment the chain declared it needs (sandbox paths it chose), added
    // to the sandbox allowlist. Nothing of the caller's environment reaches the
    // application this way.
    req.chain_env = resolution.chain.env;
    // Directories the chain needs to already exist, under the application's own
    // private data root. Proton is the case that requires this: it wants
    // STEAM_COMPAT_DATA_PATH to name an existing directory and does not create
    // one. Expressed as chain data so this loop needs no per-provider knowledge.
    for (const std::string& relative : resolution.chain.required_data_dirs) {
        // Chain-supplied, but never trusted to be relative: a chain that named
        // an absolute path or climbed out with .. would establish a directory
        // outside the application's data root.
        const fs::path candidate(relative);
        if (candidate.is_absolute()) continue;
        bool climbs = false;
        for (const fs::path& part : candidate) {
            if (part == "..") climbs = true;
        }
        if (climbs) continue;
        fs::create_directories(data_root / candidate, mkec);
    }

    // Say something before a FIRST foreign-OS launch, because it is slow and
    // silent, and those two together read as broken.
    //
    // Measured: a first Windows launch costs 150–170 seconds while the
    // per-application compatibility prefix is built, against 22 seconds once it
    // exists — and during those three minutes the runtime produces nothing at
    // all. No output, no progress, no diagnostic record; the data root quietly
    // grows. The only conclusion available to somebody who double-clicked an
    // application is that it has hung, and the natural response is to kill it,
    // which leaves a half-built prefix and makes the next attempt worse.
    //
    // "Cold" is asked of the RECORD, not of the filesystem. The obvious test —
    // did we just create the chain's required data directory — is Proton-only:
    // the wine chain declares no required directories because wine builds its
    // own prefix under the sandbox HOME, so that test would have stayed silent
    // for the chain that costs 149 seconds cold. Whether this application has
    // ever completed a launch on THIS chain is the condition that actually
    // matters, and it is the same question for every chain.
    //
    // stderr, not stdout: stdout belongs to the application; this is the runtime
    // talking. One line, and only on a first launch, so warm launches and
    // scripted reruns stay silent.
    const bool first_launch_on_this_chain =
        record.last_run_at.empty() || record.last_chain != resolution.chain.id;
    if (first_launch_on_this_chain && resolution.chain.id != "native") {
        std::fprintf(stderr,
                     "lexe: preparing the %s compatibility environment for %s. "
                     "The first launch of a Windows application takes a few "
                     "minutes; later launches do not.\n",
                     resolution.chain.id.c_str(), id.c_str());
        std::fflush(stderr);
    }

    const std::unique_ptr<IsolationBackend> backend =
        make_isolation_backend(paths);
    const IsolationCapabilities caps = backend->capabilities();

    // §5: a `service` is background by declaration — it is detached whether or
    // not the caller asked, because that is what the manifest says the
    // application IS. Any launch mode may also be detached on request (a
    // desktop handler must not block on the application it opened).
    const bool detach =
        request.detach ||
        (manifest.launch_mode == LaunchMode::Service && !request.wait_for_exit);

    // A console application with nowhere to print gets its output captured so
    // it can be shown afterwards; everything else owns our streams directly.
    // A detached launch has nobody left to show it to, so it captures nothing.
    const bool capture_output = !detach &&
        manifest.launch_mode == LaunchMode::Console && !stdout_is_terminal();

    int exit_code = 0;
    std::optional<int> signal;
    bool detached = false;
    std::string captured_stdout;
    std::string captured_stderr;
    bool output_truncated = false;
    std::uint64_t stdout_total = 0;
    std::uint64_t stderr_total = 0;
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
            if (capture_output) {
                options.tee_stdout = stdout;
                options.tee_stderr = stderr;
                options.max_retained_bytes = limits::kMaxRetainedOutputBytes;
            }
            const util::ProcessResult result = util::run_process(argv, options);
            exit_code = result.exit_code;
            signal = result.signal;
            captured_stdout = result.stdout_text;
            captured_stderr = result.stderr_text;
            output_truncated = result.stdout_truncated || result.stderr_truncated;
            stdout_total = result.stdout_total_bytes;
            stderr_total = result.stderr_total_bytes;
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
            if (capture_output) {
                plan.tee_stdout = stdout;
                plan.tee_stderr = stderr;
                plan.max_retained_bytes = limits::kMaxRetainedOutputBytes;
            }
            plan.detach = detach;
            // The lease the SUPERVISOR takes, so the version's files cannot be
            // removed under a detached application after this process — and
            // its own lease — are gone.
            plan.supervisor_lock_file =
                registry.version_lease_file(id, version).string();
            const IsolationResult result = backend->run(plan);
            exit_code = result.exit_code;
            signal = result.signal;
            captured_stdout = result.stdout_text;
            captured_stderr = result.stderr_text;
            output_truncated = result.stdout_truncated || result.stderr_truncated;
            stdout_total = result.stdout_total_bytes;
            stderr_total = result.stderr_total_bytes;
            enforced = result.enforced;
            detached = result.detached;
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
    report.detached = detached;
    report.isolation_summary = summarize_controls(enforced);

    // ------------------------------------------------ record execution report
    record.last_run_at = util::now_utc_string();
    record.last_exit_code = exit_code;
    record.last_chain = resolution.chain.id;
    record.last_launch_mode = to_string(manifest.launch_mode);
    registry.write_record(record);

    // §14.4: exit code 0 is SUCCESS even when no window appeared. Only a
    // non-zero exit or a signal produces a .lexe-error record.
    //
    // A DETACHED launch has neither: it was started and never waited for, so
    // there is no outcome to judge. Reporting one would be an invention, and
    // whatever the application does from here is its own business until the
    // next time something looks. (Nothing supervises it; see §5.)
    // The application's output has already reached the caller by now, streamed
    // through as it was produced (RunOptions::tee_stdout). Three separate
    // defects lived in what used to be here, and they are worth keeping in view
    // because each was silent:
    //
    //   * the relay wrote only stdout, and `captured_stderr` never reached our
    //     stderr in ANY branch. An application reporting on stderr and exiting 0
    //     therefore produced nothing at all, and no error record either, since
    //     those are written only for a failing exit. FORMAT-0.1 §5.6 forbids
    //     precisely that: a launch must not leave the application "silently
    //     appearing to do nothing".
    //
    //   * the relay was the ELSE of the non-zero-exit branch below, so output
    //     was withheld exactly WHEN the application exited non-zero — normal
    //     and documented for `diff`, `grep`, `test` and every compiler, where
    //     the output IS the result. It survived only inside a record the caller
    //     had to know to ask for.
    //
    //   * it wrote with `fputs`, which takes a C string, so it stopped at the
    //     application's first NUL byte. 8 MiB of binary output arrived as 163
    //     bytes; output beginning with a NUL arrived as nothing.
    //
    // And a fourth that the fix for those three introduced: relaying at exit
    // meant holding the whole output, so the launcher's memory grew with it.
    // Streaming fixes that and improves something else on the way — output now
    // appears as it is produced rather than being withheld until exit.
    //
    // The error record below is ADDITIONAL, never a substitute, and it now
    // carries a bounded SAMPLE (limits::kMaxRetainedOutputBytes) rather than the
    // whole stream. Truncation is stated in the record; a sample presented as
    // the whole thing would be a quieter version of losing the output.
    if (detached) {
        // nothing to record beyond "it started", which report.detached says
    } else if (exit_code != 0 || signal.has_value()) {
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
        // Say so when the retained copy is a sample. Without this the record
        // reads as the application's complete output and a reader would draw
        // conclusions from a truncated tail -- which is the failure this whole
        // area has produced twice already, in different clothes.
        const auto note_truncation =
            [](std::string text, bool truncated, std::uint64_t total,
               const char* stream) {
                if (!truncated) return text;
                // Says what is TRUE and nothing more, and says it at the END.
                //
                // The first version of this note claimed to be "showing the
                // first N bytes", which was wrong twice over, and finding that
                // out is the reason it now says so little. The diagnostics
                // layer already clamps a captured stream and keeps its TAIL
                // with its own marker (diagnostics.cpp, clamp_stream) — so the
                // record holds the end, not the beginning, and a smaller amount
                // than this cap. A note describing the wrong end of a different
                // quantity is worse than no note, because it is the kind of
                // detail a reader would act on.
                //
                // What this layer alone knows, and what the layer below cannot
                // recover once it has been handed a sample, is the TOTAL the
                // application wrote. So that is all it contributes. It is
                // appended rather than prepended because a tail-clamp would
                // throw away anything at the front.
                text += "\n[.LEXE: the application wrote " +
                        std::to_string(total) + " bytes to " + stream +
                        ". Every byte was delivered to the caller; this "
                        "diagnostic copy is a bounded excerpt.]\n";
                return text;
            };
        report.error = ErrorStore(paths).record(
            std::move(failure),
            note_truncation(captured_stdout, output_truncated, stdout_total,
                            "stdout"),
            note_truncation(captured_stderr, output_truncated, stderr_total,
                            "stderr"));
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

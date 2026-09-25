// ui module tests — the GTK-free presentation layer ("view model") of
// src/gui/ui.cpp, the consumer/power-user frontend:
//
//   * the command line that the .lexe handler and ".LEXE Menu" / ".LEXE Error"
//     entry points depend on;
//   * --open dispatch, which MUST follow the signed manifest role and never
//     the file name;
//   * the launch report wording, where "exit code 0 is success even when no
//     window appeared" is an architectural requirement, not a nicety;
//   * the compatibility view, which may only ever offer chains the resolver
//     actually listed;
//   * runtime/health/integration/error/uninstall/settings wording.
//
// LEXE_GUI_VIEWMODEL_ONLY makes the include below drop every GTK symbol, so
// this suite compiles and runs on hosts without GTK. Every test case
// constructs lexe::test::TempLexeHome first.

#define LEXE_GUI_VIEWMODEL_ONLY 1
#include "gui/ui.cpp"

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/appconfig.hpp"
#include "core/diagnostics.hpp"
#include "core/execpolicy.hpp"
#include "core/installer.hpp"
#include "core/integration.hpp"
#include "core/isolation.hpp"
#include "core/launcher.hpp"
#include "core/launchref.hpp"
#include "core/manifest.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/presentation.hpp"
#include "core/registry.hpp"
#include "core/verify.hpp"

#include <optional>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using lexe::Manifest;
using lexe::Paths;
using lexe::VerificationReport;
using lexe::VerificationStage;
using lexe::test::TempLexeHome;

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

std::vector<std::string> args_of(std::initializer_list<const char*> items) {
    std::vector<std::string> args;
    for (const char* item : items) args.emplace_back(item);
    return args;
}

/// An all-green §6 report, for the pure dispatch tests.
VerificationReport green_report() {
    VerificationReport report;
    for (const char* stage : {"structure", "manifest", "key",
                              "manifest-signature", "payload-signature",
                              "hashes", "payload-role", "compatibility"}) {
        report.stages.push_back(VerificationStage{stage, true, "ok", ""});
    }
    return report;
}

Manifest application_manifest() {
    return Manifest::parse(R"({
      "lexeVersion": "0.1",
      "id": "com.example.application",
      "name": "Example Application",
      "version": "1.4.2",
      "publisher": { "name": "Example Corporation",
                     "publicKey": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
      "applicationType": "native",
      "architectures": ["x86_64"],
      "entrypoint": { "executable": "bin/example" },
      "install": { "scope": "user", "mode": "bundled" }
    })");
}

Manifest launch_manifest() {
    return Manifest::parse(R"({
      "lexeVersion": "0.1",
      "id": "org.lexe.launch",
      "name": "Example Application",
      "version": "1.4.2",
      "role": "launch",
      "publisher": { "name": "Local .LEXE launch reference",
                     "publicKey": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
      "launch": { "applicationId": "com.example.application", "mode": "gui" }
    })");
}

lexe::IsolationCapabilities linux_caps() {
    lexe::IsolationCapabilities caps;
    caps.status = lexe::CapabilityStatus::Available;
    caps.backend_present = true;
    caps.user_namespaces = true;
    caps.network_namespaces = true;
    caps.bind_mounts = true;
    return caps;
}

lexe::ExecutionChain chain(const std::string& id, bool native,
                           const std::string& explanation) {
    lexe::ExecutionChain value;
    value.id = id;
    value.native = native;
    value.explanation = explanation;
    return value;
}

} // namespace

TEST_SUITE("ui") {

// ------------------------------------------------------------ command line

TEST_CASE("no arguments opens Home") {
    TempLexeHome home;
    const lexe::ui::StartRequest request = lexe::ui::parse_command_line({});
    CHECK(request.mode == lexe::ui::StartMode::Home);
    CHECK_FALSE(request.bad);
}

TEST_CASE("--open carries the artifact path (the .lexe handler entry point)") {
    TempLexeHome home;
    const lexe::ui::StartRequest request =
        lexe::ui::parse_command_line(args_of({"--open", "/tmp/App.lexe"}));
    CHECK(request.mode == lexe::ui::StartMode::OpenFile);
    CHECK(request.argument == "/tmp/App.lexe");

    // --open=<path> and a bare positional path take the same route, because a
    // desktop handler may pass the file either way.
    const lexe::ui::StartRequest equals =
        lexe::ui::parse_command_line(args_of({"--open=/tmp/App.lexe"}));
    CHECK(equals.mode == lexe::ui::StartMode::OpenFile);
    CHECK(equals.argument == "/tmp/App.lexe");

    const lexe::ui::StartRequest positional =
        lexe::ui::parse_command_line(args_of({"/tmp/run.lexe"}));
    CHECK(positional.mode == lexe::ui::StartMode::OpenFile);
    CHECK(positional.argument == "/tmp/run.lexe");
}

TEST_CASE("--app is .LEXE Menu and --errors is .LEXE Error") {
    TempLexeHome home;
    const lexe::ui::StartRequest menu =
        lexe::ui::parse_command_line(args_of({"--app", "com.example.hello"}));
    CHECK(menu.mode == lexe::ui::StartMode::AppPage);
    CHECK(menu.argument == "com.example.hello");

    const lexe::ui::StartRequest errors =
        lexe::ui::parse_command_line(args_of({"--errors", "com.example.hello"}));
    CHECK(errors.mode == lexe::ui::StartMode::ErrorHistory);
    CHECK(errors.argument == "com.example.hello");
}

TEST_CASE("a malformed command line is rejected, never silently reinterpreted") {
    TempLexeHome home;
    const lexe::ui::StartRequest unknown =
        lexe::ui::parse_command_line(args_of({"--frobnicate", "x"}));
    CHECK(unknown.mode == lexe::ui::StartMode::Usage);
    CHECK(unknown.bad);
    CHECK(contains(unknown.message, "--frobnicate"));

    // An App ID is validated before it is ever used as a path component.
    const lexe::ui::StartRequest bad_id =
        lexe::ui::parse_command_line(args_of({"--app", "../../etc/passwd"}));
    CHECK(bad_id.bad);
    CHECK(contains(bad_id.message, "not a valid application id"));

    const lexe::ui::StartRequest no_value =
        lexe::ui::parse_command_line(args_of({"--errors"}));
    CHECK(no_value.bad);

    const lexe::ui::StartRequest extra = lexe::ui::parse_command_line(
        args_of({"--app", "com.example.hello", "and-more"}));
    CHECK(extra.bad);
    CHECK(contains(extra.message, "and-more"));
}

TEST_CASE("--help prints usage and is not an error") {
    TempLexeHome home;
    const lexe::ui::StartRequest request =
        lexe::ui::parse_command_line(args_of({"--help"}));
    CHECK(request.mode == lexe::ui::StartMode::Usage);
    CHECK_FALSE(request.bad);
    CHECK(contains(request.message, "--open"));
    CHECK(contains(request.message, "--app"));
    CHECK(contains(request.message, "--errors"));
    // The single-instance promise is part of the documented contract.
    CHECK(contains(request.message, "second invocation"));
}

// -------------------------------------------------------- --open dispatch

TEST_CASE("dispatch follows the signed role: application -> install") {
    TempLexeHome home;
    const lexe::ui::OpenDispatch dispatch = lexe::ui::decide_open_dispatch(
        green_report(), application_manifest());
    CHECK(dispatch.action == lexe::ui::OpenAction::Install);
    CHECK(dispatch.application_id.empty());
    CHECK(contains(dispatch.reason, "role \"application\""));
}

TEST_CASE("dispatch follows the signed role: launch -> that application") {
    TempLexeHome home;
    const lexe::ui::OpenDispatch dispatch =
        lexe::ui::decide_open_dispatch(green_report(), launch_manifest());
    CHECK(dispatch.action == lexe::ui::OpenAction::LaunchApp);
    // The target is launch.applicationId, NOT the artifact's own id.
    CHECK(dispatch.application_id == "com.example.application");
    CHECK(contains(dispatch.reason, "role \"launch\""));
    CHECK(contains(dispatch.reason, "nothing is installed"));
}

TEST_CASE("a failed verification is never dispatched on, and names the stage") {
    TempLexeHome home;
    VerificationReport report;
    report.stages.push_back(VerificationStage{"structure", true, "ok", ""});
    report.stages.push_back(
        VerificationStage{"hashes", false, "payload/data.txt does not match", ""});
    const lexe::ui::OpenDispatch dispatch =
        lexe::ui::decide_open_dispatch(report, application_manifest());
    CHECK(dispatch.action == lexe::ui::OpenAction::Refuse);
    CHECK(contains(dispatch.reason, "hashes"));
    CHECK(contains(dispatch.reason, "Nothing was installed"));
}

TEST_CASE("an unreadable manifest is refused rather than guessed at") {
    TempLexeHome home;
    const lexe::ui::OpenDispatch dispatch =
        lexe::ui::decide_open_dispatch(green_report(), std::nullopt);
    CHECK(dispatch.action == lexe::ui::OpenAction::Refuse);
    CHECK(contains(dispatch.reason, "role is unknown"));
}

TEST_CASE("a real signed package dispatches to install") {
    TempLexeHome home;
    const auto key = lexe::test::make_keypair();
    const fs::path package = lexe::test::make_test_package(home.path(), key);

    const VerificationReport report = lexe::verify_package(package, true);
    REQUIRE(report.ok());
    lexe::PackageReader reader(package);
    const Manifest manifest = Manifest::parse(reader.read_entry("lexe.json"));

    const lexe::ui::OpenDispatch dispatch =
        lexe::ui::decide_open_dispatch(report, manifest);
    CHECK(dispatch.action == lexe::ui::OpenAction::Install);
}

TEST_CASE("a real launch reference dispatches to launch, whatever it is named") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const auto key = lexe::test::make_keypair();
    const fs::path package = lexe::test::make_test_package(home.path(), key);

    Manifest app_manifest;
    {
        lexe::PackageReader reader(package);
        app_manifest = Manifest::parse(reader.read_entry("lexe.json"));
    }
    const fs::path reference =
        lexe::create_launch_reference(paths, app_manifest);

    // Rename it to something that LOOKS like an installable application: the
    // role is signed, the file name is not, so the dispatch must not change.
    const fs::path disguised = home.path() / "TotallyAnApp.lexe";
    fs::copy_file(reference, disguised, fs::copy_options::overwrite_existing);

    const VerificationReport report = lexe::verify_package(disguised, true);
    REQUIRE(report.ok());
    lexe::PackageReader reader(disguised);
    const Manifest manifest = Manifest::parse(reader.read_entry("lexe.json"));
    REQUIRE(lexe::is_launch_reference(manifest));

    const lexe::ui::OpenDispatch dispatch =
        lexe::ui::decide_open_dispatch(report, manifest);
    CHECK(dispatch.action == lexe::ui::OpenAction::LaunchApp);
    CHECK(dispatch.application_id == app_manifest.id);
}

TEST_CASE("a launch reference for a missing application is explained plainly") {
    TempLexeHome home;
    const std::string text =
        lexe::ui::missing_launch_target_text("com.example.hello");
    CHECK(contains(text, "com.example.hello"));
    CHECK(contains(text, "not installed"));
    CHECK(contains(text, "carries no payload"));
}

// --------------------------------------------------------------- Launch

TEST_CASE("exit code 0 is reported as SUCCESS even when no window appeared") {
    TempLexeHome home;
    lexe::ExecutionReport report;
    report.id = "com.example.hello";
    report.version = "1.0.0";
    report.chain = "native";
    report.chain_reason = "host ISA matches; no layers needed";
    report.launch_mode = "console";
    report.started = true;
    report.exit_code = 0;

    const lexe::ui::LaunchLines lines =
        lexe::ui::format_execution_report(report);
    CHECK(lines.severity == "ok");
    CHECK(contains(lines.headline, "Exit code 0"));
    CHECK(contains(lines.headline, "success"));
    CHECK(contains(lines.detail, "even if no window ever appeared"));
    CHECK(contains(lines.detail, "NOT a failed launch"));
    CHECK(contains(lines.detail, "native"));
    CHECK_FALSE(lines.has_error);
}

TEST_CASE("a non-zero exit, a signal and a refusal are each distinguished") {
    TempLexeHome home;
    lexe::ExecutionReport failed;
    failed.started = true;
    failed.exit_code = 3;
    const lexe::ui::LaunchLines failed_lines =
        lexe::ui::format_execution_report(failed);
    CHECK(failed_lines.severity == "danger");
    CHECK(contains(failed_lines.headline, "exited with code 3"));

    lexe::ExecutionReport killed;
    killed.started = true;
    killed.exit_code = -1;
    killed.signal = 11;
    const lexe::ui::LaunchLines killed_lines =
        lexe::ui::format_execution_report(killed);
    CHECK(killed_lines.severity == "danger");
    CHECK(contains(killed_lines.headline, "signal 11"));

    lexe::ExecutionReport never;
    never.started = false;
    const lexe::ui::LaunchLines never_lines =
        lexe::ui::format_execution_report(never);
    CHECK(never_lines.severity == "danger");
    CHECK(contains(never_lines.headline, "was not started"));
}

TEST_CASE("a detached launch says so instead of implying an exit code") {
    TempLexeHome home;
    lexe::ExecutionReport report;
    report.started = true;
    report.detached = true;
    report.chain = "native";
    const lexe::ui::LaunchLines lines =
        lexe::ui::format_execution_report(report);
    CHECK(lines.severity == "ok");
    CHECK(contains(lines.detail, "reports no exit code"));
}

TEST_CASE("a report carrying an error record offers the error history") {
    TempLexeHome home;
    lexe::ExecutionReport report;
    report.started = true;
    report.exit_code = 1;
    lexe::ErrorRecord record;
    record.application_id = "com.example.hello";
    record.stage = lexe::FailureStage::Runtime;
    report.error = record;

    const lexe::ui::LaunchLines lines =
        lexe::ui::format_execution_report(report);
    CHECK(lines.has_error);
    CHECK(contains(lines.detail, "Error History"));

    // A refused launch (the core threw) always has a record written for it.
    const lexe::ui::LaunchLines refused =
        lexe::ui::format_launch_failure("no execution chain is available");
    CHECK(refused.has_error);
    CHECK(refused.severity == "danger");
    CHECK(contains(refused.headline, "no execution chain is available"));
    CHECK(contains(refused.detail, "was not executed"));
}

TEST_CASE("launch presentation is stated as DECLARED, not inferred") {
    TempLexeHome home;
    CHECK(contains(lexe::ui::format_launch_mode(lexe::LaunchMode::Gui),
                   "Exit code 0"));
    CHECK(contains(lexe::ui::format_launch_mode(lexe::LaunchMode::Console),
                   "terminal"));
    CHECK(contains(lexe::ui::format_launch_mode(lexe::LaunchMode::Service),
                   "background"));
    CHECK(lexe::ui::format_mission_critical(false).empty());
    const std::string critical = lexe::ui::format_mission_critical(true);
    CHECK(contains(critical, "restriction"));
    CHECK(contains(critical, "not a certification"));
}

// -------------------------------------------------------- Compatibility

TEST_CASE("only the chains the resolver listed are ever offered") {
    TempLexeHome home;
    lexe::ChainResolution resolution;
    resolution.ok = true;
    resolution.chain = chain("native", true, "runs directly on this host");
    resolution.reason = "host ISA matches the package";
    resolution.alternatives.push_back(
        chain("box64", false, "translates x86_64 to this host's ISA"));
    resolution.rejected.push_back(
        lexe::RejectedChain{"wine", "not installed on this host"});

    lexe::AppConfig config;
    config.id = "com.example.hello";
    const lexe::ui::CompatibilityView view =
        lexe::ui::build_compatibility_view(resolution, config);

    CHECK(view.resolved);
    CHECK(view.automatic);
    REQUIRE(view.options.size() == 2);
    CHECK(view.options[0].id == "native");
    CHECK(view.options[0].selected);
    CHECK(view.options[1].id == "box64");
    // A rejected chain is SHOWN with its reason, but is never selectable.
    REQUIRE(view.rejected_lines.size() == 1);
    CHECK(contains(view.rejected_lines[0], "wine"));
    CHECK(contains(view.rejected_lines[0], "not installed"));
    for (const lexe::ui::ChainOption& option : view.options) {
        CHECK(option.id != "wine");
    }
    CHECK_FALSE(view.locked);
}

TEST_CASE("a mission-critical application is locked to native, with the reason") {
    TempLexeHome home;
    lexe::ChainResolution resolution;
    resolution.ok = true;
    resolution.mission_critical = true;
    resolution.strict_resolver = true;
    resolution.chain = chain("native", true, "native execution only");
    resolution.reason = "mission-critical: native execution only";

    lexe::AppConfig config;
    const lexe::ui::CompatibilityView view =
        lexe::ui::build_compatibility_view(resolution, config);
    CHECK(view.locked);
    CHECK(contains(view.locked_reason, "mission-critical"));
    CHECK(contains(view.locked_reason, "cannot be changed"));
    REQUIRE(view.options.size() == 1);
    CHECK(view.options[0].id == "native");
}

TEST_CASE("a manual preference is reflected, and flagged when it is gone") {
    TempLexeHome home;
    lexe::ChainResolution resolution;
    resolution.ok = true;
    resolution.chain = chain("native", true, "");
    resolution.alternatives.push_back(chain("box64", false, ""));

    lexe::AppConfig manual;
    manual.compatibility_mode = lexe::CompatibilityMode::Manual;
    manual.preferred_chain = {"box64"};
    const lexe::ui::CompatibilityView chosen =
        lexe::ui::build_compatibility_view(resolution, manual);
    CHECK_FALSE(chosen.automatic);
    CHECK(chosen.manual_chain == "box64");
    CHECK(chosen.active_option == 1);
    CHECK(chosen.stale_preference.empty());

    lexe::AppConfig stale;
    stale.compatibility_mode = lexe::CompatibilityMode::Manual;
    stale.preferred_chain = {"proton"};
    const lexe::ui::CompatibilityView dropped =
        lexe::ui::build_compatibility_view(resolution, stale);
    CHECK(dropped.active_option == -1);
    CHECK(contains(dropped.stale_preference, "proton"));
    CHECK(contains(dropped.stale_preference, "Only the chains listed here"));
}

TEST_CASE("no available chain is stated plainly, with nothing to choose") {
    TempLexeHome home;
    lexe::ChainResolution resolution;
    resolution.ok = false;
    resolution.reason = "no permitted chain is available on this host";
    resolution.rejected.push_back(
        lexe::RejectedChain{"native", "package does not support this ISA"});

    const lexe::ui::CompatibilityView view =
        lexe::ui::build_compatibility_view(resolution, lexe::AppConfig{});
    CHECK_FALSE(view.resolved);
    CHECK(view.options.empty());
    CHECK(contains(view.selected_line, "No execution chain is available"));
    CHECK(contains(view.reason_line, "no permitted chain"));
}

// ------------------------------------------------------------- Runtime

TEST_CASE("the runtime block reports what install resolved, including gaps") {
    TempLexeHome home;
    lexe::InstallationRecord record;
    record.id = "com.example.hello";
    record.runtime_source = "bundled";
    record.runtime_resolved_at = "2026-09-01T10:00:00Z";
    record.runtime_glibc = "2.38";
    record.last_chain = "native";
    record.last_launch_mode = "gui";

    const std::string resolved = lexe::ui::format_runtime_block(record);
    CHECK(contains(resolved, "bundled"));
    CHECK(contains(resolved, "2026-09-01T10:00:00Z"));
    CHECK(contains(resolved, "2.38"));
    CHECK(contains(resolved, "Unresolved libraries: none"));
    CHECK(contains(resolved, "native"));

    record.runtime_unresolved = {"libfoo.so.1", "libbar.so.2"};
    const std::string unresolved = lexe::ui::format_runtime_block(record);
    CHECK(contains(unresolved, "libfoo.so.1"));
    CHECK(contains(unresolved, "libbar.so.2"));
    CHECK(contains(unresolved, "contract is not satisfied"));

    lexe::InstallationRecord never;
    CHECK(contains(lexe::ui::format_runtime_block(never), "never"));
    CHECK(contains(lexe::ui::format_runtime_block(never), "not recorded"));
}

TEST_CASE("health is reported as a passed check or a named list of issues") {
    TempLexeHome home;
    lexe::HealthReport ok;
    ok.ok = true;
    CHECK(contains(lexe::ui::format_health(ok), "passed"));

    lexe::HealthReport broken;
    broken.ok = false;
    broken.issues = {"payload/bin/hello is missing"};
    const std::string text = lexe::ui::format_health(broken);
    CHECK(contains(text, "1 issue"));
    CHECK(contains(text, "payload/bin/hello is missing"));
}

// -------------------------------------------------- Home / system health

TEST_CASE("a healthy integration tile does not ask for a repair") {
    TempLexeHome home;
    lexe::IntegrationReport report;
    report.ok = true;
    lexe::ArtifactCheck check;
    check.artifact.kind = lexe::ArtifactKind::RuntimeHandler;
    check.artifact.path = "/home/u/.local/share/applications/lexe.desktop";
    check.health = lexe::ArtifactHealth::Ok;
    report.checks.push_back(check);

    const lexe::ui::HealthTile tile = lexe::ui::build_health_tile(report);
    CHECK(tile.severity == "ok");
    CHECK_FALSE(tile.needs_repair);
    CHECK(contains(tile.headline, "in place"));
}

TEST_CASE("a broken integration names the artifact and offers a repair") {
    TempLexeHome home;
    lexe::IntegrationReport report;
    report.ok = false;
    lexe::ArtifactCheck missing;
    missing.artifact.kind = lexe::ArtifactKind::LaunchReference;
    missing.artifact.path = "/home/u/.local/share/lexe/launch/app.lexe";
    missing.health = lexe::ArtifactHealth::Missing;
    missing.detail = "the file is gone";
    report.checks.push_back(missing);
    report.unregistered_apps.push_back("com.example.hello");

    const lexe::ui::HealthTile tile = lexe::ui::build_health_tile(report);
    CHECK(tile.severity == "caution");
    CHECK(tile.needs_repair);
    CHECK(contains(tile.headline, "2 integration problems"));
    CHECK(contains(tile.detail, "/home/u/.local/share/lexe/launch/app.lexe"));
    CHECK(contains(tile.detail, "com.example.hello"));
    CHECK(contains(tile.detail, "no package file is needed"));
}

TEST_CASE("the installed count is plain language, including the empty case") {
    TempLexeHome home;
    CHECK(contains(lexe::ui::format_installed_count(0), "No applications"));
    CHECK(contains(lexe::ui::format_installed_count(1), "1 application is"));
    CHECK(contains(lexe::ui::format_installed_count(4), "4 applications are"));
}

// -------------------------------------------------------- Error History

TEST_CASE("an error row names time, stage, exit/signal and summary") {
    TempLexeHome home;
    lexe::ErrorRecord record;
    record.timestamp = "2026-09-24T12:00:00Z";
    record.stage = lexe::FailureStage::RuntimeResolution;
    record.execution_chain = "native";
    record.exit_code = 127;
    record.summary = "libfoo.so.1 could not be resolved";

    const std::string row = lexe::ui::format_error_row(record);
    CHECK(contains(row, "2026-09-24T12:00:00Z"));
    CHECK(contains(row, lexe::to_string(lexe::FailureStage::RuntimeResolution)));
    CHECK(contains(row, "exit 127"));
    CHECK(contains(row, "native"));
    CHECK(contains(row, "libfoo.so.1"));
}

TEST_CASE("an empty history explains what empty means") {
    TempLexeHome home;
    const std::string text =
        lexe::ui::format_error_history_empty("com.example.hello");
    CHECK(contains(text, "com.example.hello"));
    CHECK(contains(text, "nothing has failed"));
}

TEST_CASE("error records round-trip through the store into the rows") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const lexe::ErrorStore store(paths);

    lexe::ErrorRecord record;
    record.application_id = "com.example.hello";
    record.stage = lexe::FailureStage::Launch;
    record.summary = "the entrypoint could not be executed";
    record.detail = "exec failed";
    record.execution_chain = "native";
    record.timestamp = "2026-09-24T12:00:00Z";
    const lexe::ErrorRecord stored = store.record(record, "out", "err");
    CHECK_FALSE(stored.record_path.empty());

    const std::vector<lexe::ErrorRecord> history =
        store.history("com.example.hello");
    REQUIRE(history.size() == 1);
    CHECK(contains(lexe::ui::format_error_row(history[0]),
                   "the entrypoint could not be executed"));
    // "Copy Error Details" copies the store's own details text, not ours.
    CHECK(contains(history[0].to_details_text(), "com.example.hello"));
}

// ------------------------------------------------------------ Uninstall

TEST_CASE("each uninstall mode says exactly what it deletes") {
    TempLexeHome home;
    using Mode = lexe::Installer::UninstallMode;
    const std::string app_only =
        lexe::ui::uninstall_mode_description(Mode::AppOnly);
    CHECK(contains(app_only, "data and its cache are kept"));

    const std::string with_cache =
        lexe::ui::uninstall_mode_description(Mode::AppAndCache);
    CHECK(contains(with_cache, "cache"));
    CHECK(contains(with_cache, "data is still kept"));

    const std::string purge =
        lexe::ui::uninstall_mode_description(Mode::PurgeData);
    CHECK(contains(purge, "persistent data"));
    CHECK(contains(purge, "cannot be undone"));

    CHECK(contains(lexe::ui::uninstall_mode_label(Mode::AppOnly), "keep my data"));
    CHECK(contains(lexe::ui::uninstall_mode_label(Mode::PurgeData),
                   "including my data"));
}

TEST_CASE("the uninstall confirmation states the data outcome either way") {
    TempLexeHome home;
    using Mode = lexe::Installer::UninstallMode;
    const std::string keep = lexe::ui::uninstall_confirmation(
        "Hello App", "com.example.hello", Mode::AppOnly);
    CHECK(contains(keep, "Hello App"));
    CHECK(contains(keep, "com.example.hello"));
    CHECK(contains(keep, "saved data is NOT deleted"));

    const std::string purge = lexe::ui::uninstall_confirmation(
        "Hello App", "com.example.hello", Mode::PurgeData);
    CHECK(contains(purge, "permanently deletes the saved data"));
}

// ---------------------------------------------------------- Apps list

TEST_CASE("the last-run line distinguishes never-run from exit 0") {
    TempLexeHome home;
    CHECK(contains(lexe::ui::format_last_run("", 0), "Never launched"));
    CHECK(contains(lexe::ui::format_last_run("2026-09-24T12:00:00Z", 0),
                   "exited 0 (success)"));
    CHECK(contains(lexe::ui::format_last_run("2026-09-24T12:00:00Z", 2),
                   "exited 2"));
}

TEST_CASE("local trust is presented as LOCAL, never as an identity check") {
    TempLexeHome home;
    const std::string none = lexe::ui::format_local_trust(std::nullopt);
    CHECK(contains(none, "No local signing-key record"));

    lexe::TrustRecord known;
    known.app_id = "com.example.hello";
    known.first_seen = "2026-09-01T10:00:00Z";
    const std::string seen = lexe::ui::format_local_trust(known);
    CHECK(contains(seen, "2026-09-01T10:00:00Z"));
    CHECK(contains(seen, "not a check of the publisher's identity"));

    lexe::TrustRecord explicit_trust = known;
    explicit_trust.explicitly_trusted = true;
    const std::string trusted = lexe::ui::format_local_trust(explicit_trust);
    CHECK(contains(trusted, "a local decision only"));
    CHECK(contains(trusted, "not a check of the publisher's identity"));

    lexe::TrustRecord blocked = known;
    blocked.blocked = true;
    blocked.blocked_at = "2026-09-10T10:00:00Z";
    CHECK(contains(lexe::ui::format_local_trust(blocked), "Locally blocked"));
}

TEST_CASE("an app row combines the record, the manifest and the trust record") {
    TempLexeHome home;
    lexe::InstallationRecord record;
    record.id = "com.example.hello";
    record.version = "1.0.0";
    record.last_run_at = "2026-09-24T12:00:00Z";
    record.last_exit_code = 0;
    record.last_chain = "native";

    const lexe::ui::AppRow row =
        lexe::ui::build_app_row(record, application_manifest(), std::nullopt);
    CHECK(row.id == "com.example.hello");
    CHECK(row.title == "Example Application");
    CHECK(contains(row.subtitle, "Version 1.0.0"));
    CHECK(contains(row.subtitle, "com.example.hello"));
    CHECK(contains(row.subtitle, "native"));
    CHECK(contains(row.last_run, "success"));

    // Without a manifest the row falls back to the id — never to a guess.
    const lexe::ui::AppRow bare =
        lexe::ui::build_app_row(record, std::nullopt, std::nullopt);
    CHECK(bare.title == "com.example.hello");
}

// ---------------------------------------------------------- Permissions

TEST_CASE("permissions are rendered from presentation::present_permissions") {
    TempLexeHome home;
    const std::vector<lexe::presentation::PermissionView> views =
        lexe::presentation::present_permissions({"network",
                                                 "user-files-selected"},
                                                linux_caps());
    const std::string text = lexe::ui::format_permission_rows(views);
    CHECK(contains(text, "Network access"));
    CHECK(contains(text, "enforced"));
    CHECK(contains(text, "advisory"));
    CHECK(lexe::ui::format_permission_rows({}) ==
          "This application requests no permissions.");
}

TEST_CASE("the approved permission set is shown separately from the request") {
    TempLexeHome home;
    CHECK(contains(lexe::ui::format_approved_permissions({}),
                   "No permissions were approved"));
    const std::string approved =
        lexe::ui::format_approved_permissions({"network"});
    CHECK(contains(approved, "Approved for the installed version"));
    CHECK(contains(approved, "Network access"));
}

// ---------------------------------------------------------- Diagnostics

TEST_CASE("the locations block lists every per-application root") {
    TempLexeHome home;
    lexe::ui::AppLocations locations;
    locations.version_dir = "/apps/com.example.hello/versions/1.0.0";
    locations.data_dir = "/data/com.example.hello";
    locations.cache_dir = "/cache/apps/com.example.hello";
    locations.error_dir = "/state/errors/com.example.hello";
    locations.launch_reference = "/launch/com.example.hello.lexe";
    locations.config_file = "/config/apps/com.example.hello.json";

    const std::string text = lexe::ui::format_app_locations(locations);
    CHECK(contains(text, locations.version_dir));
    CHECK(contains(text, locations.data_dir));
    CHECK(contains(text, locations.cache_dir));
    CHECK(contains(text, locations.error_dir));
    CHECK(contains(text, locations.launch_reference));
    CHECK(contains(text, locations.config_file));
}

TEST_CASE("the copy-diagnostics payload is self-contained") {
    TempLexeHome home;
    lexe::InstallationRecord record;
    record.id = "com.example.hello";
    record.version = "1.0.0";
    record.installed_at = "2026-09-01T10:00:00Z";
    record.source = "/tmp/hello.lexe";
    record.runtime_source = "bundled";

    lexe::ui::AppLocations locations;
    locations.error_dir = "/state/errors/com.example.hello";

    const std::string text = lexe::ui::format_diagnostics_text(
        "0.1.0-alpha", "Linux 6.16 (Fedora 44)", "x86_64", record, locations,
        "Chain: native", "Health check passed", "Desktop integration is in place");
    CHECK(contains(text, "0.1.0-alpha"));
    CHECK(contains(text, "Fedora 44"));
    CHECK(contains(text, "x86_64"));
    CHECK(contains(text, "com.example.hello"));
    CHECK(contains(text, "Chain: native"));
    CHECK(contains(text, "Health check passed"));
    CHECK(contains(text, "Desktop integration is in place"));
    CHECK(contains(text, "/state/errors/com.example.hello"));
    CHECK(contains(text, "bundled"));
}

TEST_CASE("the chain summary names the policy and what was not used") {
    TempLexeHome home;
    lexe::ChainResolution resolution;
    resolution.ok = true;
    resolution.chain = chain("native", true, "");
    resolution.reason = "host ISA matches";
    resolution.rejected.push_back(
        lexe::RejectedChain{"fex", "not installed on this host"});

    const std::string text = lexe::ui::format_chain_summary(resolution);
    CHECK(contains(text, "Chain: native"));
    CHECK(contains(text, "host ISA matches"));
    CHECK(contains(text, "normal compatibility resolution"));
    CHECK(contains(text, "fex"));

    resolution.mission_critical = true;
    CHECK(contains(lexe::ui::format_chain_summary(resolution),
                   "mission-critical"));
}

// ------------------------------------------------------------- Settings

TEST_CASE("every settings key has a title, help and a control shape") {
    TempLexeHome home;
    for (const std::string& key : lexe::Settings::keys()) {
        CHECK_FALSE(lexe::ui::setting_title(key).empty());
        CHECK_FALSE(lexe::ui::setting_help(key).empty());
        if (lexe::ui::setting_is_boolean(key)) {
            CHECK(lexe::ui::setting_choices(key).empty());
        } else {
            CHECK_FALSE(lexe::ui::setting_choices(key).empty());
        }
    }
    CHECK(lexe::ui::setting_choices("theme") ==
          std::vector<std::string>{"system", "light", "dark"});
    CHECK(lexe::ui::setting_choices("updateCheck") ==
          std::vector<std::string>{"manual", "never"});
}

TEST_CASE("every offered settings value is one the core actually accepts") {
    TempLexeHome home;
    for (const std::string& key : lexe::Settings::keys()) {
        lexe::Settings settings;
        if (lexe::ui::setting_is_boolean(key)) {
            CHECK_NOTHROW(settings.set(key, "true"));
            CHECK_NOTHROW(settings.set(key, "false"));
        } else {
            for (const std::string& value : lexe::ui::setting_choices(key)) {
                CHECK_NOTHROW(settings.set(key, value));
            }
        }
    }
}

TEST_CASE("settings are scoped: they never weaken a security guarantee") {
    TempLexeHome home;
    const std::string note = lexe::ui::settings_scope_note();
    CHECK(contains(note, "always enforced"));
    CHECK(contains(note, "not settings"));
}

TEST_CASE("handler registration state is reported from the recorded artifacts") {
    TempLexeHome home;
    lexe::IntegrationReport empty;
    CHECK(contains(lexe::ui::format_handler_state(empty),
                   "No .LEXE handler registration"));

    lexe::IntegrationReport healthy;
    lexe::ArtifactCheck mime;
    mime.artifact.kind = lexe::ArtifactKind::RuntimeMime;
    mime.health = lexe::ArtifactHealth::Ok;
    lexe::ArtifactCheck handler;
    handler.artifact.kind = lexe::ArtifactKind::RuntimeHandler;
    handler.health = lexe::ArtifactHealth::Ok;
    healthy.checks = {mime, handler};
    const std::string ok_text = lexe::ui::format_handler_state(healthy);
    CHECK(contains(ok_text, "registered and unchanged"));
    CHECK(contains(ok_text, "survives logout and reboot"));

    lexe::IntegrationReport broken = healthy;
    broken.checks[1].health = lexe::ArtifactHealth::Missing;
    const std::string broken_text = lexe::ui::format_handler_state(broken);
    CHECK(contains(broken_text, "needs repair"));
    CHECK(contains(broken_text, "handler entry"));
}

// ------------------------------------------------ truthfulness invariant

TEST_CASE("the frontend never claims 'verified', 'trusted', 'safe' or 'secure' "
          "on its own authority") {
    TempLexeHome home;
    // Everything this layer writes about trust, permissions and isolation is
    // routed through presentation.hpp; these are the strings it composes
    // itself, and none of them may assert any of those words unqualified.
    std::vector<std::string> composed;
    composed.push_back(lexe::ui::usage_text());
    composed.push_back(lexe::ui::format_local_trust(std::nullopt));
    composed.push_back(lexe::ui::format_installed_count(3));
    composed.push_back(lexe::ui::format_last_run("2026-09-24T12:00:00Z", 0));
    composed.push_back(lexe::ui::format_launch_mode(lexe::LaunchMode::Gui));
    composed.push_back(lexe::ui::format_mission_critical(true));
    composed.push_back(lexe::ui::settings_scope_note());
    composed.push_back(
        lexe::ui::missing_launch_target_text("com.example.hello"));
    using Mode = lexe::Installer::UninstallMode;
    for (Mode mode : {Mode::AppOnly, Mode::AppAndCache, Mode::PurgeData}) {
        composed.push_back(lexe::ui::uninstall_mode_label(mode));
        composed.push_back(lexe::ui::uninstall_mode_description(mode));
    }
    lexe::TrustRecord record;
    record.explicitly_trusted = true;
    record.first_seen = "2026-09-01T10:00:00Z";
    composed.push_back(lexe::ui::format_local_trust(record));

    for (const std::string& text : composed) {
        CAPTURE(text);
        CHECK_FALSE(contains(text, "is safe"));
        CHECK_FALSE(contains(text, "is secure"));
        CHECK_FALSE(contains(text, "Verified"));
        CHECK_FALSE(contains(text, "is verified"));
        CHECK_FALSE(contains(text, "Trusted publisher"));
    }
    // The one place "trusted" appears at all is immediately qualified as a
    // LOCAL decision, never as an identity or safety claim.
    const std::string trusted = lexe::ui::format_local_trust(record);
    REQUIRE(contains(trusted, "trusted"));
    CHECK(contains(trusted, "on this machine"));
    CHECK(contains(trusted, "a local decision only"));
}

} // TEST_SUITE("ui")

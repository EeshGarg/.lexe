// gui module tests — the GTK-free presentation layer ("view model") of
// src/gui/main.cpp: the SPEC primary-screen strings plus the runtime-trust
// WS10 two-dimensional authenticity + local-trust banner, per-permission
// enforcement, and the isolation summary.
//
// LEXE_GUI_VIEWMODEL_ONLY makes the include below drop every GTK symbol, so
// this suite compiles and runs on hosts without GTK (the Windows dev host).
// Every test case constructs lexe::test::TempLexeHome first.

#define LEXE_GUI_VIEWMODEL_ONLY 1
#include "gui/main.cpp"

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/isolation.hpp"
#include "core/manifest.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/permissions.hpp"
#include "core/presentation.hpp"
#include "core/trust.hpp"
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

std::optional<Manifest> try_read_manifest(const fs::path& package) {
    try {
        lexe::PackageReader reader(package);
        return Manifest::parse(reader.read_entry("lexe.json"));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

lexe::IsolationCapabilities linux_caps() {
    lexe::IsolationCapabilities c;
    c.status = lexe::CapabilityStatus::Available;
    c.backend_present = true;
    c.user_namespaces = true;
    c.network_namespaces = true;
    c.bind_mounts = true;
    return c;
}

/// What the GUI main() does: compute the trust evaluation + isolation caps and
/// build the view model. `caps` is fixed here so the strings are deterministic.
lexe::gui::ViewModel make_vm(const std::optional<Manifest>& manifest,
                             const VerificationReport& report,
                             const fs::path& package, const Paths& paths,
                             const lexe::PermissionDelta& delta = {}) {
    std::optional<lexe::TrustEvaluation> eval;
    if (manifest.has_value()) {
        eval = lexe::TrustStore(paths).evaluate(
            manifest->id, manifest->decoded_public_key(),
            lexe::signature_state_from_report(report), std::nullopt);
    }
    return lexe::gui::build_view_model(manifest, report, package, paths,
                                       "x86_64", eval, linux_caps(), delta);
}

} // namespace

TEST_SUITE("gui") {

TEST_CASE("format_size renders decimal human sizes (SPEC mock: 126 MB)") {
    TempLexeHome home;
    CHECK(lexe::gui::format_size(0) == "0 B");
    CHECK(lexe::gui::format_size(1500) == "1.5 KB");
    CHECK(lexe::gui::format_size(125829120) == "126 MB");
    CHECK(lexe::gui::format_size(2500000000ULL) == "2.5 GB");
}

TEST_CASE("describe_permission maps permission ids to user language") {
    TempLexeHome home;
    CHECK(lexe::gui::describe_permission("network") == "Network access");
    CHECK(lexe::gui::describe_permission("user-files-selected") ==
          "Access to files you select");
    CHECK(lexe::gui::describe_permission("quantum-entangler") ==
          "quantum-entangler"); // unknown ids pass through
}

TEST_CASE("format_permissions shows each permission with its enforcement") {
    TempLexeHome home;
    CHECK(lexe::gui::format_permissions({}, linux_caps()) == "None requested");
    const std::string text =
        lexe::gui::format_permissions({"network", "user-files-selected"}, linux_caps());
    CHECK(contains(text, "Network access"));
    CHECK(contains(text, "enforced")); // network is enforced with net namespaces
    CHECK(contains(text, "Access to files you select"));
    CHECK(contains(text, "advisory")); // user-files-selected is advisory in 0.1
}

TEST_CASE("format_application_type produces 'Native Linux - <arch>'") {
    TempLexeHome home;
    CHECK(lexe::gui::format_application_type("native", {"x86_64", "aarch64"},
                                             "x86_64") == "Native Linux — x86_64");
    CHECK(lexe::gui::format_application_type("native", {"aarch64"}, "x86_64") ==
          "Native Linux — aarch64");
}

TEST_CASE("format_install shows scope and size") {
    TempLexeHome home;
    CHECK(lexe::gui::format_install("user", 125829120) ==
          "Current user only\n126 MB");
}

TEST_CASE("format_updates states the source + channel, or that updates are off") {
    TempLexeHome home;
    CHECK(contains(lexe::gui::format_updates(true, "https://e/u.json", "stable"),
                   "Automatically check"));
    // "No automatic updates" rather than "updates are disabled": a package can
    // have updates enabled and simply no manifest URL to check, and this line
    // has to be true in both cases.
    CHECK(lexe::gui::format_updates(false, "https://e/u.json", "stable") ==
          "No automatic updates");
    CHECK(lexe::gui::format_updates(true, "", "stable") == "No automatic updates");
}

// --- one wording, both frontends ------------------------------------------
//
// The CLI and the Installer each used to format these facts themselves, and the
// copies drifted: the Installer called a permission "Access to files you select"
// where the vocabulary said "choose", wrote an em dash in the type line where
// the CLI wrote a hyphen, and said "All users (system-wide)" where the CLI said
// "System-wide". These lock every frontend to core/presentation so a future
// change cannot re-fork the wording without failing here.

TEST_CASE("the GUI formats package facts through core/presentation, not its own") {
    TempLexeHome home;
    namespace pres = lexe::presentation;

    CHECK(lexe::gui::format_size(125829120) == pres::format_size(125829120));
    CHECK(lexe::gui::describe_permission("user-files-selected") ==
          pres::describe_permission("user-files-selected"));
    CHECK(lexe::gui::format_application_type("native", {"x86_64"}, "x86_64") ==
          pres::application_type_line("native", {"x86_64"}, "x86_64"));
    CHECK(lexe::gui::format_updates(true, "https://e/u.json", "stable") ==
          pres::updates_line(true, "https://e/u.json", "stable"));
    CHECK(lexe::gui::format_source("bundled", "app.lexe") ==
          pres::source_line("bundled", "app.lexe"));
    CHECK(contains(lexe::gui::format_install("user", 125829120),
                   pres::install_scope_line("user")));
}

TEST_CASE("an update that expands permissions is flagged for a consent gate") {
    // The Installer used to SAY "separate approval required" and offer no way to
    // give that approval: it never set allow_permission_expansion, so every
    // press of Install failed with "requests permissions you have not approved"
    // and the only way through was `lexe install --accept-permissions`. The view
    // model now reports the expansion so the window can show a consent box and
    // keep Install disabled until it is ticked.
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const auto key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);
    const VerificationReport report =
        lexe::verify_package(pkg, /*check_architecture=*/false);
    const std::optional<Manifest> manifest = try_read_manifest(pkg);
    REQUIRE(manifest.has_value());

    // No previously approved set -> adding "network" is an expansion.
    const lexe::PermissionDelta expanding = lexe::permission_delta(
        lexe::normalize_permissions({}), lexe::normalize_permissions({"network"}));
    REQUIRE(expanding.expands());
    const lexe::gui::ViewModel grew =
        make_vm(manifest, report, pkg, paths, expanding);
    CHECK(grew.permission_expansion);
    CHECK_FALSE(grew.permission_delta_text.empty());
    CHECK(contains(grew.permission_delta_text, "Network access"));

    // Same permissions already approved -> nothing new, no consent gate.
    const lexe::PermissionDelta unchanged = lexe::permission_delta(
        lexe::normalize_permissions({"network"}),
        lexe::normalize_permissions({"network"}));
    CHECK_FALSE(unchanged.expands());
    const lexe::gui::ViewModel same =
        make_vm(manifest, report, pkg, paths, unchanged);
    CHECK_FALSE(same.permission_expansion);
    CHECK(same.permission_delta_text.empty());
}

TEST_CASE("permission wording comes from the frozen vocabulary, not a copy") {
    TempLexeHome home;
    // Every id in the vocabulary must render through the GUI exactly as the
    // vocabulary titles it — the Installer previously carried its own list,
    // including nine permissions that do not exist in 0.1 at all.
    for (const lexe::PermissionSpec& spec : lexe::permission_vocabulary()) {
        INFO("permission: " << spec.id);
        CHECK(lexe::gui::describe_permission(spec.id) == spec.title);
        CHECK(contains(lexe::gui::format_permissions({spec.id}, linux_caps()),
                       spec.title));
    }
}

TEST_CASE("channel options cover stable/beta/nightly and keep custom channels") {
    TempLexeHome home;
    const auto custom = lexe::gui::channel_options("lts");
    REQUIRE(custom == std::vector<std::string>{"lts", "stable", "beta", "nightly"});
    CHECK(lexe::gui::channel_active_index(custom, "lts") == 0);
}

TEST_CASE("format_trust presents authenticity + local trust, first-seen is caution") {
    TempLexeHome home;
    const auto key = lexe::test::make_keypair();

    // First-seen valid signature: caution, NOT a green "verified".
    lexe::TrustEvaluation fs_eval;
    fs_eval.app_id = "com.example.hello";
    fs_eval.signature = lexe::SignatureState::Valid;
    fs_eval.key_state = lexe::PublisherKeyState::FirstSeen;
    fs_eval.decision = lexe::TrustDecision::AllowFirstInstall;
    fs_eval.presented = lexe::key_fingerprint(key.public_key);
    const lexe::gui::TrustLines fs_lines = lexe::gui::format_trust(fs_eval);
    CHECK(fs_lines.severity == "caution");
    CHECK(fs_lines.allowed);
    CHECK(contains(fs_lines.headline, "first seen"));
    CHECK(fs_lines.fingerprint.size() > 0);

    // A changed key is danger and disables proceeding.
    lexe::TrustEvaluation changed = fs_eval;
    changed.key_state = lexe::PublisherKeyState::Changed;
    changed.decision = lexe::TrustDecision::RejectChangedKey;
    changed.app_id = "com.example.hello";
    changed.expected = lexe::key_fingerprint(lexe::test::make_keypair().public_key);
    const lexe::gui::TrustLines ch = lexe::gui::format_trust(changed);
    CHECK(ch.severity == "danger");
    CHECK_FALSE(ch.allowed);

    // A "the signing key has changed" screen showed only the key in front of
    // you, so there was nothing to compare it against, and offered no way
    // forward at all. Both fingerprints, and the procedure that actually
    // clears it — removing the application ALONE does not, because the local
    // trust record survives.
    CHECK_FALSE(ch.expected_fingerprint.empty());
    CHECK(ch.expected_fingerprint != ch.fingerprint);
    CHECK(contains(ch.remedy, "lexe remove com.example.hello --purge-data"));
    CHECK(contains(ch.remedy, "lexe trust forget com.example.hello"));

    // A key that has NOT changed has nothing to compare and nothing to remedy.
    CHECK(fs_lines.expected_fingerprint.empty());
    CHECK(fs_lines.remedy.empty());

    // No evaluation (unreadable package): danger, cannot establish authenticity.
    const lexe::gui::TrustLines none = lexe::gui::format_trust(std::nullopt);
    CHECK(none.severity == "danger");
    CHECK(contains(none.headline, "could not be read"));
}

TEST_CASE("format_isolation states the truthful control set") {
    TempLexeHome home;
    const std::string text = lexe::gui::format_isolation(linux_caps());
    CHECK(contains(text, "enforced"));
    CHECK(contains(text, "advisory"));           // file selection
    CHECK(contains(text, "not implemented"));    // seccomp
    CHECK(contains(text, "GUI forwarding"));
}

TEST_CASE("format_advanced_directories lists every FORMAT-0.1 §9 location") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const std::string text =
        lexe::gui::format_advanced_directories(paths, "com.example.hello");
    CHECK(contains(text, (paths.apps_dir() / "com.example.hello").string()));
    CHECK(contains(text, (paths.data_dir() / "com.example.hello").string()));
}

TEST_CASE("verified first-seen package yields an installable, cautioned screen") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const auto key = lexe::test::make_keypair();
    const fs::path package = lexe::test::make_test_package(home.path(), key);

    const VerificationReport report =
        lexe::verify_package(package, /*check_architecture=*/true);
    REQUIRE(report.ok());
    const std::optional<Manifest> manifest = try_read_manifest(package);
    REQUIRE(manifest.has_value());

    const lexe::gui::ViewModel vm = make_vm(manifest, report, package, paths);

    CHECK(vm.verified);
    CHECK(vm.can_install); // valid signature + first-seen key IS installable
    CHECK(vm.app_id == "com.example.hello");
    CHECK(vm.app_name == "Hello App");
    CHECK(contains(vm.publisher_line, "Published by Test Publisher"));
    CHECK(contains(vm.publisher_line, "not independently verified"));
    CHECK(vm.version_line == "Version 1.0.0");
    CHECK(vm.type_text == "Native Linux — x86_64");
    CHECK(vm.permissions_text == "None requested");
    // Two-dimensional trust, not a single "Verified".
    CHECK(vm.trust_severity == "caution");
    CHECK(contains(vm.status_text, "first seen"));
    CHECK(vm.fingerprint_text.size() > 0);
    CHECK(contains(vm.identity_caveat, "real-world identity"));
    CHECK(contains(vm.isolation_text, "seccomp"));
}

TEST_CASE("tampered payload disables Install and says what actually failed") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const auto key = lexe::test::make_keypair();
    const fs::path package = lexe::test::make_test_package(home.path(), key);
    lexe::test::tamper_entry(package, "payload/data.txt",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE_FALSE(bytes.empty());
                                 bytes[0] ^= 0xFF;
                             });

    const VerificationReport report = lexe::verify_package(package, true);
    REQUIRE_FALSE(report.ok());
    CHECK(report.first_failure()->name == "hashes");
    const std::optional<Manifest> manifest = try_read_manifest(package);
    REQUIRE(manifest.has_value());

    const lexe::gui::ViewModel vm = make_vm(manifest, report, package, paths);
    CHECK_FALSE(vm.verified);
    CHECK_FALSE(vm.can_install);
    CHECK(vm.trust_severity == "danger");

    // The security property: refused, whatever it is called.
    CHECK_FALSE(vm.can_install);

    // The honesty property: the signatures over this package DID verify — a
    // covered file no longer matches the hashes they sign. Saying "signature is
    // not valid" here was simply untrue, and this runtime does not tell users
    // untrue things about authenticity.
    CHECK(contains(vm.status_text, "contents do not match"));
    CHECK_FALSE(contains(vm.status_text, "signature is not valid"));
    CHECK(contains(vm.signature_text, "valid, but the package contents"));

    // And it must name the stage that failed, the way `lexe verify` does —
    // a missing file, a corrupt payload and a bad signature used to render
    // an identical screen.
    CHECK(contains(vm.refusal_text, "hashes"));
    CHECK_FALSE(vm.refusal_text.empty());
}

TEST_CASE("a package that verifies has nothing to explain") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const auto key = lexe::test::make_keypair();
    const fs::path package = lexe::test::make_test_package(home.path(), key);
    const VerificationReport report = lexe::verify_package(package, true);
    REQUIRE(report.ok());
    const std::optional<Manifest> manifest = try_read_manifest(package);
    const lexe::gui::ViewModel vm = make_vm(manifest, report, package, paths);
    CHECK(vm.verified);
    CHECK(vm.refusal_text.empty());
}

TEST_CASE("unreadable package still yields a safe, uninstallable screen") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path package = home.path() / "broken.lexe";
    lexe::util::spit(package, std::string_view("this is not a zip archive"));

    const VerificationReport report = lexe::verify_package(package, true);
    REQUIRE_FALSE(report.ok());
    const std::optional<Manifest> manifest = try_read_manifest(package);
    CHECK_FALSE(manifest.has_value());

    const lexe::gui::ViewModel vm = make_vm(manifest, report, package, paths);
    CHECK_FALSE(vm.verified);
    CHECK_FALSE(vm.can_install);
    CHECK(vm.app_name == "broken.lexe");
    CHECK(vm.publisher_line == "Publisher unknown");
    CHECK(vm.trust_severity == "danger");
    CHECK(contains(vm.status_text, "could not be read"));
}

TEST_CASE("view model reflects SPEC manifest example fields") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const std::string json = R"({
      "lexeVersion": "0.1",
      "id": "com.example.application",
      "name": "Example Application",
      "version": "1.4.2",
      "publisher": {
        "name": "Example Corporation",
        "website": "https://example.com",
        "publicKey": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      },
      "applicationType": "native",
      "architectures": ["x86_64", "aarch64"],
      "entrypoint": { "executable": "bin/example", "arguments": [] },
      "install": { "scope": "user", "mode": "bundled",
                   "estimatedSize": 125829120 },
      "permissions": ["network", "user-files-selected"],
      "updates": { "enabled": true, "channel": "stable",
                   "manifest": "https://example.com/releases/update.json",
                   "allowSourceChange": true }
    })";
    const Manifest m = Manifest::parse(json);

    VerificationReport report; // synthetic all-green report
    for (const char* stage : {"structure", "manifest", "key",
                              "manifest-signature", "payload-signature",
                              "hashes", "compatibility"}) {
        report.stages.push_back(VerificationStage{stage, true, "ok"});
    }

    const lexe::gui::ViewModel vm = make_vm(m, report,
                                            fs::path("ExampleApplication.lexe"), paths);

    CHECK(vm.app_name == "Example Application");
    CHECK(contains(vm.publisher_line, "Published by Example Corporation"));
    CHECK(contains(vm.publisher_line, "not independently verified"));
    CHECK(vm.version_line == "Version 1.4.2");
    CHECK(vm.type_text == "Native Linux — x86_64");
    CHECK(contains(vm.permissions_text, "Network access"));
    CHECK(contains(vm.permissions_text, "Access to files you select"));
    CHECK(vm.install_text == "Current user only\n126 MB");
    // "After install:" answers where it goes and how to undo it, by id.
    CHECK(contains(vm.after_install_text, "home directory"));
    CHECK(contains(vm.after_install_text, "lexe remove com.example.application"));
    CHECK(contains(vm.after_install_text, "purge-data"));
    // "Verify later:" answers whether trust can be re-checked after install.
    CHECK(contains(vm.verify_later_text, "every launch"));
    CHECK(contains(vm.verify_later_text, "lexe inspect"));
    CHECK(contains(vm.verify_later_text, "lexe repair"));
    CHECK(vm.verified);
    CHECK(vm.can_install); // first-seen but valid → installable
    CHECK(vm.trust_severity == "caution");
}

} // TEST_SUITE("gui")

// gui module tests — the GTK-free presentation layer ("view model") of
// src/gui/main.cpp: the strings of the SPEC "User Interface" primary screen
// (size, permissions, type/arch, scope, source, update policy), the
// verification status banner (a failed FORMAT-0.1 §6 stage names itself and
// disables Install), channel options, and the full view model built from
// real verified/tampered/broken packages.
//
// LEXE_GUI_VIEWMODEL_ONLY makes the include below drop every GTK symbol, so
// this suite compiles and runs on hosts without GTK (the Windows dev host).
// The GTK layer itself is compile-gated by the Linux CI `lexe-installer`
// target. Every test case constructs lexe::test::TempLexeHome first.

#define LEXE_GUI_VIEWMODEL_ONLY 1
#include "gui/main.cpp"

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/manifest.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
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

/// What the GUI's main() does to obtain the manifest for display: read
/// lexe.json out of the package, empty on any failure.
std::optional<Manifest> try_read_manifest(const fs::path& package) {
    try {
        lexe::PackageReader reader(package);
        return Manifest::parse(reader.read_entry("lexe.json"));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace

TEST_SUITE("gui") {

TEST_CASE("format_size renders decimal human sizes (SPEC mock: 126 MB)") {
    TempLexeHome home;
    CHECK(lexe::gui::format_size(0) == "0 B");
    CHECK(lexe::gui::format_size(1) == "1 B");
    CHECK(lexe::gui::format_size(999) == "999 B");
    CHECK(lexe::gui::format_size(1500) == "1.5 KB");
    CHECK(lexe::gui::format_size(9999) == "10.0 KB");
    CHECK(lexe::gui::format_size(250000) == "250 KB");
    // The SPEC manifest example: estimatedSize 125829120 shown as "126 MB".
    CHECK(lexe::gui::format_size(125829120) == "126 MB");
    CHECK(lexe::gui::format_size(2500000000ULL) == "2.5 GB");
    CHECK(lexe::gui::format_size(3200000000000ULL) == "3.2 TB");
}

TEST_CASE("describe_permission maps SPEC permission ids to user language") {
    TempLexeHome home;
    CHECK(lexe::gui::describe_permission("network") == "Network access");
    CHECK(lexe::gui::describe_permission("user-files-selected") ==
          "Access to files you select");
    CHECK(lexe::gui::describe_permission("user-files-all") ==
          "Access to all of your files");
    CHECK(lexe::gui::describe_permission("microphone") == "Microphone access");
    CHECK(lexe::gui::describe_permission("camera") == "Camera access");
    // Unknown ids must pass through verbatim — never hidden from the user.
    CHECK(lexe::gui::describe_permission("quantum-entangler") ==
          "quantum-entangler");
}

TEST_CASE("format_permissions mirrors the SPEC primary-screen mock") {
    TempLexeHome home;
    CHECK(lexe::gui::format_permissions({}) == "None requested");
    // SPEC mock: Permissions: Network access / Access to files you select.
    CHECK(lexe::gui::format_permissions({"network", "user-files-selected"}) ==
          "Network access\nAccess to files you select");
}

TEST_CASE("format_application_type produces 'Native Linux — <arch>'") {
    TempLexeHome home;
    // Host architecture supported: show exactly it (SPEC mock).
    CHECK(lexe::gui::format_application_type(
              "native", {"x86_64", "aarch64"}, "x86_64") ==
          "Native Linux — x86_64");
    CHECK(lexe::gui::format_application_type("native", {"aarch64", "x86_64"},
                                             "aarch64") ==
          "Native Linux — aarch64");
    // Host not supported: list what the package offers instead.
    CHECK(lexe::gui::format_application_type("native", {"aarch64"}, "x86_64") ==
          "Native Linux — aarch64");
    CHECK(lexe::gui::format_application_type(
              "native", {"x86_64", "aarch64"}, "riscv64") ==
          "Native Linux — x86_64, aarch64");
    // Degenerate inputs stay readable.
    CHECK(contains(lexe::gui::format_application_type("native", {}, "x86_64"),
                   "unknown architecture"));
}

TEST_CASE("format_install shows scope and size per the SPEC mock") {
    TempLexeHome home;
    CHECK(lexe::gui::format_install_scope("user") == "Current user only");
    CHECK(lexe::gui::format_install_scope("system") ==
          "All users (system-wide)");
    CHECK(lexe::gui::format_install("user", 125829120) ==
          "Current user only\n126 MB");
    CHECK(lexe::gui::format_install("user", 0) ==
          "Current user only\nInstall size not specified");
}

TEST_CASE("format_source names the bundled package file") {
    TempLexeHome home;
    const std::string text =
        lexe::gui::format_source("bundled", "ExampleApplication.lexe");
    CHECK(contains(text, "Bundled"));
    CHECK(contains(text, "ExampleApplication.lexe"));
    CHECK(contains(lexe::gui::format_source("network", "x.lexe"),
                   "unsupported in Lexe 0.1"));
}

TEST_CASE("format_updates states the source + channel, or that updates are off") {
    TempLexeHome home;
    const std::string enabled = lexe::gui::format_updates(
        true, "https://example.com/releases/update.json", "stable");
    CHECK(contains(enabled, "Automatically check"));
    CHECK(contains(enabled, "https://example.com/releases/update.json"));
    CHECK(contains(enabled, "stable"));

    CHECK(lexe::gui::format_updates(false, "https://example.com/u.json",
                                    "stable") ==
          "Updates are disabled for this package.");
    CHECK(lexe::gui::format_updates(true, "", "stable") ==
          "Updates are disabled for this package.");
}

TEST_CASE("channel options cover stable/beta/nightly and keep custom channels") {
    TempLexeHome home;
    const auto standard = lexe::gui::channel_options("stable");
    REQUIRE(standard == std::vector<std::string>{"stable", "beta", "nightly"});
    CHECK(lexe::gui::channel_active_index(standard, "stable") == 0);
    CHECK(lexe::gui::channel_active_index(standard, "beta") == 1);
    CHECK(lexe::gui::channel_active_index(standard, "nightly") == 2);
    // Empty configured channel falls back to stable.
    CHECK(lexe::gui::channel_active_index(standard, "") == 0);
    // A non-standard manifest channel is preserved and preselected.
    const auto custom = lexe::gui::channel_options("lts");
    REQUIRE(custom ==
            std::vector<std::string>{"lts", "stable", "beta", "nightly"});
    CHECK(lexe::gui::channel_active_index(custom, "lts") == 0);
}

TEST_CASE("format_verification_status distinguishes pass, fail and no-run") {
    TempLexeHome home;

    VerificationReport empty;
    CHECK(contains(lexe::gui::format_verification_status(empty),
                   "could not be performed"));

    VerificationReport good;
    good.stages.push_back(VerificationStage{"structure", true, "ok"});
    good.stages.push_back(VerificationStage{"manifest", true, "ok"});
    CHECK(contains(lexe::gui::format_verification_status(good), "Verified"));

    // A failure names the FORMAT-0.1 §6 stage, the reason, and states that
    // installation is disabled (SPEC: users must understand what they trust).
    VerificationReport bad;
    bad.stages.push_back(VerificationStage{"structure", true, "ok"});
    bad.stages.push_back(
        VerificationStage{"manifest-signature", false, "signature mismatch"});
    const std::string text = lexe::gui::format_verification_status(bad);
    CHECK(contains(text, "FAILED"));
    CHECK(contains(text, "manifest-signature"));
    CHECK(contains(text, "signature mismatch"));
    CHECK(contains(text, "Installation is disabled"));
}

TEST_CASE("format_advanced_directories lists every FORMAT-0.1 §9 location") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const std::string text =
        lexe::gui::format_advanced_directories(paths, "com.example.hello");
    CHECK(contains(text,
                   (paths.apps_dir() / "com.example.hello").string()));
    CHECK(contains(text,
                   (paths.data_dir() / "com.example.hello").string()));
    CHECK(contains(text, paths.applications_dir().string()));
    CHECK(contains(text, paths.icons_dir().string()));
    CHECK(contains(text, paths.cache_dir().string()));
}

TEST_CASE("verified package yields an installable primary screen") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const auto key = lexe::test::make_keypair();
    const fs::path package = lexe::test::make_test_package(home.path(), key);

    const VerificationReport report =
        lexe::verify_package(package, /*check_architecture=*/true);
    REQUIRE(report.ok());
    const std::optional<Manifest> manifest = try_read_manifest(package);
    REQUIRE(manifest.has_value());

    const lexe::gui::ViewModel vm = lexe::gui::build_view_model(
        manifest, report, package, paths, "x86_64");

    CHECK(vm.verified);
    CHECK(vm.can_install);
    CHECK(vm.app_id == "com.example.hello");
    CHECK(vm.app_name == "Hello App");
    CHECK(vm.publisher_line == "Published by Test Publisher");
    CHECK(vm.version_line == "Version 1.0.0");
    CHECK(vm.type_text == "Native Linux — x86_64");
    CHECK(vm.permissions_text == "None requested");
    CHECK(contains(vm.install_text, "Current user only"));
    CHECK(contains(vm.source_text, package.filename().string()));
    // No updates block in the default test manifest.
    CHECK(vm.updates_text == "Updates are disabled for this package.");
    CHECK(contains(vm.status_text, "Verified"));
    CHECK(contains(vm.advanced_dirs_text,
                   (paths.apps_dir() / "com.example.hello").string()));
    REQUIRE_FALSE(vm.channels.empty());
    CHECK(vm.channels[static_cast<std::size_t>(vm.active_channel)] == "stable");
}

TEST_CASE("package with an updates block yields channel-aware update text") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const auto key = lexe::test::make_keypair();
    lexe::test::TestAppSpec spec;
    spec.update_url = "https://updates.example.com/update.json";
    const fs::path package =
        lexe::test::make_test_package(home.path(), key, spec);

    const VerificationReport report = lexe::verify_package(package, true);
    REQUIRE(report.ok());
    const std::optional<Manifest> manifest = try_read_manifest(package);
    REQUIRE(manifest.has_value());

    const lexe::gui::ViewModel vm = lexe::gui::build_view_model(
        manifest, report, package, paths, "x86_64");

    CHECK(contains(vm.updates_text, "Automatically check"));
    CHECK(contains(vm.updates_text, "https://updates.example.com/update.json"));
    CHECK(contains(vm.updates_text, "stable"));
    REQUIRE_FALSE(vm.channels.empty());
    CHECK(vm.channels[static_cast<std::size_t>(vm.active_channel)] == "stable");
}

TEST_CASE("tampered payload disables Install and names the hashes stage") {
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
    REQUIRE(report.first_failure() != nullptr);
    CHECK(report.first_failure()->name == "hashes");

    // lexe.json is untouched, so the screen can still show the app details —
    // but the banner names the failed stage and Install stays disabled.
    const std::optional<Manifest> manifest = try_read_manifest(package);
    REQUIRE(manifest.has_value());

    const lexe::gui::ViewModel vm = lexe::gui::build_view_model(
        manifest, report, package, paths, "x86_64");

    CHECK_FALSE(vm.verified);
    CHECK_FALSE(vm.can_install);
    CHECK(vm.app_name == "Hello App");
    CHECK(contains(vm.status_text, "FAILED"));
    CHECK(contains(vm.status_text, "hashes"));
    CHECK(contains(vm.status_text, "Installation is disabled"));
}

TEST_CASE("unreadable package still yields a safe, uninstallable screen") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path package = home.path() / "broken.lexe";
    lexe::util::spit(package, std::string_view("this is not a zip archive"));

    const VerificationReport report = lexe::verify_package(package, true);
    REQUIRE_FALSE(report.ok());
    REQUIRE(report.first_failure() != nullptr);
    CHECK(report.first_failure()->name == "structure");

    const std::optional<Manifest> manifest = try_read_manifest(package);
    CHECK_FALSE(manifest.has_value());

    const lexe::gui::ViewModel vm = lexe::gui::build_view_model(
        manifest, report, package, paths, "x86_64");

    CHECK_FALSE(vm.verified);
    CHECK_FALSE(vm.can_install);
    CHECK(vm.app_name == "broken.lexe"); // falls back to the file name
    CHECK(vm.publisher_line == "Publisher unknown");
    CHECK(contains(vm.permissions_text, "could not be read"));
    CHECK(contains(vm.status_text, "FAILED"));
    CHECK(contains(vm.status_text, "structure"));
    // The channel combo still offers sane defaults.
    REQUIRE_FALSE(vm.channels.empty());
    CHECK(vm.channels[static_cast<std::size_t>(vm.active_channel)] == "stable");
}

TEST_CASE("view model reflects SPEC manifest example fields") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    // The SPEC "Application Manifest" example, verbatim where relevant.
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

    const lexe::gui::ViewModel vm = lexe::gui::build_view_model(
        m, report, fs::path("ExampleApplication.lexe"), paths, "x86_64");

    // SPEC "Opening a .lexe File" mock, field by field.
    CHECK(vm.app_name == "Example Application");
    CHECK(vm.publisher_line ==
          "Published by Example Corporation (https://example.com)");
    CHECK(vm.version_line == "Version 1.4.2");
    CHECK(vm.type_text == "Native Linux — x86_64");
    CHECK(vm.permissions_text ==
          "Network access\nAccess to files you select");
    CHECK(vm.install_text == "Current user only\n126 MB");
    CHECK(contains(vm.updates_text,
                   "https://example.com/releases/update.json"));
    CHECK(vm.verified);
    CHECK(vm.can_install);
}

} // TEST_SUITE("gui")

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
#include "core/settings.hpp"
#include "core/presentation.hpp"
#include "core/transaction.hpp"
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

// --- never a heading over an empty body -----------------------------------
//
// format_trust(nullopt) used to set the headline ALONE, leaving signature, key,
// fingerprint and caveat empty — so the details page drew the bold
// "Authenticity & local trust:" heading with nothing whatsoever under it. It
// read as a label that had failed to render, and it left unanswered the only
// question that section exists to answer: was a signing key checked at all?

TEST_CASE("an absent trust evaluation still fills the authenticity section") {
    TempLexeHome home;

    // Undecodable file: no manifest, therefore no key to check anything against.
    const lexe::gui::TrustLines unreadable = lexe::gui::format_trust(std::nullopt);
    CHECK(unreadable.severity == "danger");
    CHECK_FALSE(unreadable.allowed);          // still fails closed
    CHECK_FALSE(unreadable.signature.empty()); // the defect: these were empty
    CHECK_FALSE(unreadable.key.empty());
    CHECK(contains(unreadable.headline, "could not be read"));
    // It must say a key was never obtained, not stay silent about it.
    CHECK(contains(unreadable.key, "could not be read"));
    // Nothing may be claimed about a key that was never seen.
    CHECK(unreadable.fingerprint.empty());
    CHECK(unreadable.expected_fingerprint.empty());
    CHECK(unreadable.caveat.empty());

    // The other way an evaluation goes missing: the manifest read fine and
    // TrustStore::evaluate failed. Describing that with "this package could not
    // be read" would be untrue — the package read perfectly.
    const lexe::gui::TrustLines no_record =
        lexe::gui::format_trust(std::nullopt, /*manifest_readable=*/true);
    CHECK(no_record.severity == "danger");
    CHECK_FALSE(no_record.allowed);
    CHECK_FALSE(no_record.signature.empty());
    CHECK_FALSE(no_record.key.empty());
    CHECK_FALSE(contains(no_record.headline, "package could not be read"));
    CHECK(contains(no_record.headline, "trust could not be evaluated"));
}

TEST_CASE("the authenticity section body is never empty, for any package") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const auto key = lexe::test::make_keypair();

    // (1) A package that verifies.
    const fs::path good = lexe::test::make_test_package(home.path(), key);
    const VerificationReport good_report = lexe::verify_package(good, true);
    const lexe::gui::ViewModel good_vm =
        make_vm(try_read_manifest(good), good_report, good, paths);
    CHECK_FALSE(lexe::gui::trust_section_body(good_vm).empty());
    CHECK(contains(lexe::gui::trust_section_body(good_vm),
                   good_vm.signature_text));
    CHECK(contains(lexe::gui::trust_section_body(good_vm),
                   good_vm.fingerprint_text));

    // (2) A package whose payload was tampered with (signature valid, contents
    //     do not match) — an evaluation exists.
    const fs::path bad_dir = home.path() / "tampered";
    fs::create_directories(bad_dir);
    const fs::path bad = lexe::test::make_test_package(bad_dir, key);
    lexe::test::tamper_entry(bad, "payload/data.txt",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE_FALSE(bytes.empty());
                                 bytes[0] ^= 0xFF;
                             });
    const VerificationReport bad_report = lexe::verify_package(bad, true);
    const lexe::gui::ViewModel bad_vm =
        make_vm(try_read_manifest(bad), bad_report, bad, paths);
    CHECK_FALSE(lexe::gui::trust_section_body(bad_vm).empty());

    // (3) The defect's own case: an undecodable file. No manifest, no
    //     evaluation, and previously an entirely empty section body.
    const fs::path junk = home.path() / "undecodable.lexe";
    lexe::util::spit(junk, std::string_view("\x7f\xde\xad\xbe\xef not a zip"));
    const VerificationReport junk_report = lexe::verify_package(junk, true);
    const std::optional<Manifest> junk_manifest = try_read_manifest(junk);
    REQUIRE_FALSE(junk_manifest.has_value());
    const lexe::gui::ViewModel junk_vm =
        make_vm(junk_manifest, junk_report, junk, paths);

    const std::string body = lexe::gui::trust_section_body(junk_vm);
    CHECK_FALSE(body.empty());
    CHECK_FALSE(junk_vm.signature_text.empty());
    CHECK_FALSE(junk_vm.key_text.empty());
    // Fails closed, exactly as before.
    CHECK_FALSE(junk_vm.can_install);
    CHECK(junk_vm.trust_severity == "danger");

    // The page already has a "Why this package was refused:" section that names
    // the failing pipeline stage. This section must not say it a second time.
    REQUIRE_FALSE(junk_vm.refusal_text.empty());
    REQUIRE(junk_report.first_failure() != nullptr);
    CHECK(contains(junk_vm.refusal_text, junk_report.first_failure()->name));
    CHECK_FALSE(contains(body, junk_report.first_failure()->name));
    CHECK_FALSE(contains(body, "Verification failed"));
}

// --- progress: the stage that is actually running --------------------------
//
// The progress screen was a spinner over one fixed line, so a five-second
// install and a wedged one looked identical. Installer::install() takes no
// progress callback, but it does write every phase transition to the
// transaction journal before doing that phase's work — so the stage the GUI
// names is read from the installer's own on-disk state, never guessed from a
// timer.

TEST_CASE("every transaction phase maps to the stage that phase performs") {
    TempLexeHome home;
    using lexe::TxnPhase;
    using lexe::gui::InstallStage;
    using lexe::gui::install_stage_from_phase;

    // No journal yet: what runs before InstallTransaction::begin() is the §6
    // pipeline and the trust/permission gates.
    CHECK(install_stage_from_phase(TxnPhase::None) == InstallStage::Verifying);
    CHECK(install_stage_from_phase(TxnPhase::Preparing) ==
          InstallStage::Extracting);
    CHECK(install_stage_from_phase(TxnPhase::Staged) == InstallStage::Rechecking);
    CHECK(install_stage_from_phase(TxnPhase::Verified) == InstallStage::Placing);
    CHECK(install_stage_from_phase(TxnPhase::Promoted) ==
          InstallStage::Activating);
    CHECK(install_stage_from_phase(TxnPhase::RecordUpdated) ==
          InstallStage::Finishing);

    // The screen only ever moves forward, so the ranks must increase in the
    // order the phases actually occur. The journal is DELETED on commit, which
    // reads back as TxnPhase::None; without a strict ordering the screen would
    // announce "verifying" again at the instant the install succeeded.
    const TxnPhase order[] = {TxnPhase::None,     TxnPhase::Preparing,
                              TxnPhase::Staged,   TxnPhase::Verified,
                              TxnPhase::Promoted, TxnPhase::RecordUpdated};
    for (std::size_t i = 1; i < std::size(order); ++i) {
        INFO("phase: " << lexe::to_string(order[i]));
        CHECK(lexe::gui::install_stage_rank(install_stage_from_phase(order[i])) >
              lexe::gui::install_stage_rank(
                  install_stage_from_phase(order[i - 1])));
    }
}

TEST_CASE("each stage says something, and no two stages say the same thing") {
    TempLexeHome home;
    using lexe::gui::InstallStage;
    const InstallStage stages[] = {
        InstallStage::Verifying, InstallStage::Extracting,
        InstallStage::Rechecking, InstallStage::Placing,
        InstallStage::Activating, InstallStage::Finishing};
    std::vector<std::string> seen;
    for (const InstallStage stage : stages) {
        const std::string text = lexe::gui::install_stage_text(stage);
        CHECK_FALSE(text.empty());
        // No percentage, no ETA, no "N%" — the installer publishes phases, not
        // byte counts, and a fraction here would be an invention.
        CHECK_FALSE(contains(text, "%"));
        CHECK(std::find(seen.begin(), seen.end(), text) == seen.end());
        seen.push_back(text);
    }
    // install_stage_rank must index install_stage_text: on_progress_tick stores
    // the rank and casts it back to a stage.
    for (const InstallStage stage : stages) {
        CHECK(lexe::gui::install_stage_text(static_cast<InstallStage>(
                  lexe::gui::install_stage_rank(stage))) ==
              lexe::gui::install_stage_text(stage));
    }
}

TEST_CASE("elapsed time is rendered as a clock, and never runs backwards") {
    TempLexeHome home;
    CHECK(lexe::gui::format_elapsed(0) == "0:00");
    CHECK(lexe::gui::format_elapsed(7) == "0:07");
    CHECK(lexe::gui::format_elapsed(70) == "1:10");
    CHECK(lexe::gui::format_elapsed(599) == "9:59");
    CHECK(lexe::gui::format_elapsed(3600) == "1:00:00");
    CHECK(lexe::gui::format_elapsed(3930) == "1:05:30");
    // A monotonic clock cannot go backwards, but a defensive clamp keeps a
    // negative from formatting as "0:-5" if one ever did.
    CHECK(lexe::gui::format_elapsed(-5) == "0:00");
}

TEST_CASE("the progress note explains the wait without offering an unsafe stop") {
    TempLexeHome home;
    const std::string note = lexe::gui::install_progress_note();
    CHECK_FALSE(note.empty());
    // It must say WHY waiting is safe: nothing is switched over until the whole
    // staged tree has been re-checked (HARDENING.md §A).
    CHECK(contains(note, "re-checked"));
    // And it must be honest that there is no cancel, rather than implying one.
    CHECK(contains(note, "no Cancel"));
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

// --- the theme control -----------------------------------------------------
//
// The installer window's theme control and `lexe config set theme` have to be
// ONE preference. The tests below pin the two ends of that: the control offers
// exactly the values Settings accepts, and what the control writes is what a
// later load reads back.

TEST_CASE("the theme control offers exactly the values settings accept") {
    TempLexeHome home;
    const std::vector<std::string>& values = lexe::gui::theme_option_values();

    // Three, not two: "follow the desktop" is a distinct answer from "light",
    // and a two-state control cannot express it.
    REQUIRE(values.size() == 3);
    CHECK(values[0] == "system"); // the default, and index 0
    CHECK(values[1] == "light");
    CHECK(values[2] == "dark");
    CHECK(lexe::gui::theme_option_labels().size() == values.size());

    // Every offered value is one Settings::set accepts. If the vocabulary ever
    // grows on one side only, this fails instead of the GUI throwing on a
    // click.
    for (const std::string& value : values) {
        lexe::Settings settings;
        REQUIRE_NOTHROW(settings.set("theme", value));
        CHECK(settings.theme == value);
        CHECK(settings.get("theme") == value);
    }
    lexe::Settings settings;
    CHECK_THROWS_AS(settings.set("theme", "midnight"), lexe::Error);
    // GTK reports -1 for "no active item"; that must not become an empty string
    // handed to Settings::set, which would throw on a cosmetic change.
    CHECK_THROWS_AS(settings.set("theme", ""), lexe::Error);
}

TEST_CASE("a theme choice round-trips through the persisted settings file") {
    TempLexeHome home;
    const Paths paths = Paths::detect();

    // What the window does at startup: read the preference, select that option.
    lexe::Settings loaded = lexe::Settings::load(paths);
    CHECK(loaded.theme == "system");
    CHECK(lexe::gui::theme_option_index(loaded.theme) == 0);

    // What the window does when the user picks "Dark": take the value for the
    // selected index, set it, save it. Other preferences must survive — the
    // window keeps the whole bundle rather than saving a fresh default one.
    loaded.developer_mode = true;
    loaded.update_check = "never";
    loaded.set("theme", lexe::gui::theme_option_value(2));
    loaded.save(paths);

    const lexe::Settings reread = lexe::Settings::load(paths);
    CHECK(reread.theme == "dark");
    CHECK(reread.developer_mode);              // not clobbered by the theme write
    CHECK(reread.update_check == "never");
    CHECK(lexe::gui::theme_option_index(reread.theme) == 2);
}

TEST_CASE("an unknown or out-of-range theme falls back to following the desktop") {
    TempLexeHome home;
    // A settings.json written by a newer runtime must not leave the control
    // showing nothing selected while the window renders the system palette.
    CHECK(lexe::gui::theme_option_index("solarized") == 0);
    CHECK(lexe::gui::theme_option_index("") == 0);
    CHECK(lexe::gui::theme_option_value(-1) == "system");
    CHECK(lexe::gui::theme_option_value(3) == "system");
    for (int i = 0; i < 3; ++i) {
        CHECK(lexe::gui::theme_option_index(lexe::gui::theme_option_value(i)) == i);
    }
}

// --- drag and drop ---------------------------------------------------------
//
// A dropped file is untrusted input that arrived by mouse. check_dropped_package
// decides only whether the drag delivered one local .lexe worth opening; every
// refusal must SAY something, because a drop that changes nothing on screen is
// indistinguishable from a drop target that does not work.

TEST_CASE("a dropped single .lexe file is accepted for verification") {
    TempLexeHome home;
    const auto key = lexe::test::make_keypair();
    const fs::path package = lexe::test::make_test_package(home.path(), key);

    const lexe::gui::DropCheck check =
        lexe::gui::check_dropped_package({package.string()});
    CHECK(check.accept);
    CHECK(check.path == package);
    CHECK(check.message.empty());
}

TEST_CASE("a package whose extension was upcased by the filesystem is accepted") {
    TempLexeHome home;
    const auto key = lexe::test::make_keypair();
    const fs::path package = lexe::test::make_test_package(home.path(), key);
    // A package carried on a FAT or ISO-9660 volume comes back upcased.
    // Refusing it there would be a false rejection the user cannot act on.
    const fs::path upcased = home.path() / "HELLO.LEXE";
    fs::copy_file(package, upcased);

    const lexe::gui::DropCheck check =
        lexe::gui::check_dropped_package({upcased.string()});
    CHECK(check.accept);
    CHECK(check.path == upcased);
}

TEST_CASE("every refused drop says why, and never yields a path to open") {
    TempLexeHome home;
    const auto key = lexe::test::make_keypair();
    const fs::path package = lexe::test::make_test_package(home.path(), key);

    struct Case {
        const char* what;
        std::vector<std::string> paths;
        const char* must_mention;
    };

    // A folder, including one NAMED like a package: an unpacked project
    // directory is exactly what a developer drags by mistake, and it must be
    // named as a folder rather than reported as an unreadable archive.
    const fs::path folder = home.path() / "some-folder";
    fs::create_directories(folder);
    const fs::path folder_named_lexe = home.path() / "project.lexe";
    fs::create_directories(folder_named_lexe);
    const fs::path not_a_package = home.path() / "notes.txt";
    lexe::util::spit(not_a_package, std::string_view("not a package\n"));
    const fs::path missing = home.path() / "gone.lexe";

    const std::vector<Case> cases{
        {"nothing at all", {}, "no file"},
        {"two packages", {package.string(), package.string()}, "one package"},
        {"a remote or virtual location", {std::string()}, "local file"},
        {"a folder", {folder.string()}, "folder"},
        {"a folder named like a package", {folder_named_lexe.string()}, "folder"},
        {"a file that is not a package", {not_a_package.string()}, ".lexe"},
        {"a path that does not exist", {missing.string()}, "not a readable file"},
    };

    for (const Case& c : cases) {
        CAPTURE(c.what);
        const lexe::gui::DropCheck check =
            lexe::gui::check_dropped_package(c.paths);
        CHECK_FALSE(check.accept);
        // The defect this guards: a silently ignored drop.
        CHECK_FALSE(check.message.empty());
        CHECK(contains(check.message, c.must_mention));
        // Nothing refused may hand a path on to the verification pipeline.
        CHECK(check.path.empty());
    }
}

TEST_CASE("dropping a package does not shorten the route to Install") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const auto key = lexe::test::make_keypair();

    // A real package, dropped: admitted by the drop check, and then judged by
    // the SAME view model a command-line argument produces. Being dropped is
    // worth nothing on its own.
    const fs::path good = lexe::test::make_test_package(home.path(), key);
    const lexe::gui::DropCheck good_drop =
        lexe::gui::check_dropped_package({good.string()});
    REQUIRE(good_drop.accept);
    const VerificationReport good_report =
        lexe::verify_package(good_drop.path, true);
    const lexe::gui::ViewModel good_vm =
        make_vm(try_read_manifest(good_drop.path), good_report, good_drop.path,
                paths);
    CHECK(good_vm.can_install);

    // A package with a tampered payload, dropped. It is still a .lexe file, so
    // the drop check admits it — and it must be REFUSED by the pipeline, with
    // Install disabled, exactly as it would be from the command line.
    const fs::path bad_dir = home.path() / "tampered";
    fs::create_directories(bad_dir);
    const fs::path bad = lexe::test::make_test_package(bad_dir, key);
    lexe::test::tamper_entry(bad, "payload/data.txt",
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE_FALSE(bytes.empty());
                                 bytes[0] ^= 0xFF;
                             });
    const lexe::gui::DropCheck bad_drop =
        lexe::gui::check_dropped_package({bad.string()});
    REQUIRE(bad_drop.accept); // admission is not approval
    const VerificationReport bad_report =
        lexe::verify_package(bad_drop.path, true);
    const lexe::gui::ViewModel bad_vm = make_vm(
        try_read_manifest(bad_drop.path), bad_report, bad_drop.path, paths);
    CHECK_FALSE(bad_vm.verified);
    CHECK_FALSE(bad_vm.can_install);
    CHECK(bad_vm.trust_severity == "danger");
    CHECK_FALSE(bad_vm.refusal_text.empty());

    // Bytes that are not an archive at all, named .lexe. Same story.
    const fs::path junk = home.path() / "junk.lexe";
    lexe::util::spit(junk, std::string_view("\x7f not a zip"));
    const lexe::gui::DropCheck junk_drop =
        lexe::gui::check_dropped_package({junk.string()});
    REQUIRE(junk_drop.accept);
    const VerificationReport junk_report =
        lexe::verify_package(junk_drop.path, true);
    const lexe::gui::ViewModel junk_vm =
        make_vm(try_read_manifest(junk_drop.path), junk_report, junk_drop.path,
                paths);
    CHECK_FALSE(junk_vm.can_install);
}

TEST_CASE("the empty state offers both ways in, and promises no shortcut") {
    TempLexeHome home;
    const lexe::gui::DropZoneText text = lexe::gui::drop_zone_text();
    // Launching with no argument used to be a modal usage error and exit(2).
    // The replacement has to name both routes: someone who started the window
    // from a desktop menu has no command line to add an argument to, and
    // someone who has one should not have to guess the syntax.
    CHECK(contains(text.title, ".lexe"));
    CHECK(contains(text.command, "lexe-installer"));
    CHECK(contains(text.command, ".lexe"));
    CHECK(contains(text.hint, "command line"));
    // And it must not imply that dropping is the easy way past the checks.
    CHECK(contains(text.assurance, "verification"));
    CHECK_FALSE(text.assurance.empty());
}

} // TEST_SUITE("gui")

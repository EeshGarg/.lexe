// builder module tests — the GTK-free presentation/validation layer ("view
// model") of src/gui/builder.cpp: manifest JSON construction from a form
// struct (valid + round-trips through Manifest::parse), form validation
// accept/reject tables, and entrypoint enumeration of a temp folder.
//
// LEXE_GUI_VIEWMODEL_ONLY makes the include below drop every GTK symbol, so
// this suite compiles and runs on hosts without GTK (the Windows dev host).
// The GTK layer itself is compile-gated by the Linux `lexe-builder` target.

#define LEXE_GUI_VIEWMODEL_ONLY 1
#include "gui/builder.cpp"

#include <doctest/doctest.h>

#include "elf_builder.hpp"
#include "helpers.hpp"

#include "core/manifest.hpp"
#include "core/util.hpp"

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using lexe::Manifest;
using lexe::gui::BuilderForm;
using lexe::test::TempLexeHome;

// A structurally valid FORMAT-0.1 §4 publisher key (base64 of 32 zero bytes).
// Manifest::parse checks presence/string-ness only, not decodability, so this
// is enough to exercise manifest construction round-trips.
const std::string kZeroKey =
    "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

/// A fully valid form (the accept baseline; individual reject tests mutate it).
BuilderForm valid_form() {
    BuilderForm form;
    form.app_id = "com.example.app";
    form.name = "Example App";
    form.version = "1.2.3";
    form.entrypoint = "bin/example";
    form.publisher_name = "Example Corporation";
    form.arch_x86_64 = true;
    form.arch_aarch64 = true;
    form.perm_network = true;
    form.perm_user_files_selected = true;
    form.available_entrypoints = {"bin/example", "data/config.json"};
    return form;
}

} // namespace

TEST_SUITE("builder") {

TEST_CASE("build_manifest_json produces a valid manifest that round-trips") {
    TempLexeHome home;
    const BuilderForm form = valid_form();

    const std::string json = lexe::gui::build_manifest_json(form, kZeroKey);
    const Manifest m = Manifest::parse(json); // throws on any §5 violation

    CHECK(m.lexe_version == "0.1");
    CHECK(m.id == "com.example.app");
    CHECK(m.name == "Example App");
    CHECK(m.version == "1.2.3");
    CHECK(m.publisher_name == "Example Corporation");
    CHECK(m.publisher_public_key == kZeroKey);
    CHECK(m.application_type == "native");
    CHECK(m.architectures == std::vector<std::string>{"x86_64", "aarch64"});
    CHECK(m.entrypoint_executable == "bin/example");
    CHECK(m.install_mode == "bundled");
    CHECK(m.install_scope == "user");
    CHECK(m.permissions ==
          std::vector<std::string>{"network", "user-files-selected"});
}

TEST_CASE("build_manifest_json honours single-arch / no-permission forms") {
    TempLexeHome home;
    BuilderForm form = valid_form();
    form.arch_aarch64 = false;
    form.perm_network = false;
    form.perm_user_files_selected = false;
    form.publisher_website = "https://example.com";

    const std::string json = lexe::gui::build_manifest_json(form, kZeroKey);
    const Manifest m = Manifest::parse(json);

    CHECK(m.architectures == std::vector<std::string>{"x86_64"});
    CHECK(m.permissions.empty());
    CHECK(m.publisher_website == "https://example.com");
}

TEST_CASE("validate_form accepts a well-formed form") {
    const lexe::gui::ValidationResult r =
        lexe::gui::validate_form(valid_form());
    CHECK(r.ok);
    CHECK(r.error.empty());
}

TEST_CASE("validate_form rejects a bad reverse-DNS id") {
    BuilderForm form = valid_form();
    form.app_id = "notreversedns"; // single segment
    lexe::gui::ValidationResult r = lexe::gui::validate_form(form);
    CHECK_FALSE(r.ok);
    CHECK(contains(r.error, "reverse-DNS"));

    form.app_id = "com..example"; // empty middle segment
    CHECK_FALSE(lexe::gui::validate_form(form).ok);

    form.app_id = "com.exa mple.app"; // space not allowed
    CHECK_FALSE(lexe::gui::validate_form(form).ok);

    form.app_id = "com.example."; // trailing dot
    CHECK_FALSE(lexe::gui::validate_form(form).ok);
}

TEST_CASE("validate_form rejects empty required fields") {
    {
        BuilderForm form = valid_form();
        form.app_id.clear();
        CHECK_FALSE(lexe::gui::validate_form(form).ok);
    }
    {
        BuilderForm form = valid_form();
        form.name.clear();
        CHECK_FALSE(lexe::gui::validate_form(form).ok);
    }
    {
        BuilderForm form = valid_form();
        form.version.clear();
        CHECK_FALSE(lexe::gui::validate_form(form).ok);
    }
    {
        BuilderForm form = valid_form();
        form.publisher_name.clear();
        CHECK_FALSE(lexe::gui::validate_form(form).ok);
    }
}

TEST_CASE("validate_form rejects a missing architecture selection") {
    BuilderForm form = valid_form();
    form.arch_x86_64 = false;
    form.arch_aarch64 = false;
    const lexe::gui::ValidationResult r = lexe::gui::validate_form(form);
    CHECK_FALSE(r.ok);
    CHECK(contains(r.error, "architecture"));
}

TEST_CASE("validate_form rejects an entrypoint not in the folder") {
    BuilderForm form = valid_form();

    // No entrypoint chosen at all.
    form.entrypoint.clear();
    CHECK_FALSE(lexe::gui::validate_form(form).ok);

    // Chosen, but not among the folder's files.
    form.entrypoint = "bin/does-not-exist";
    const lexe::gui::ValidationResult r = lexe::gui::validate_form(form);
    CHECK_FALSE(r.ok);
    CHECK(contains(r.error, "not a file in the selected folder"));
}

TEST_CASE("enumerate_entrypoints lists regular files as relative '/'-paths") {
    TempLexeHome home;
    const fs::path folder = home.path() / "appfiles";
    lexe::util::spit(folder / "run.sh", std::string_view("#!/bin/sh\n"));
    lexe::util::spit(folder / "bin" / "tool", std::string_view("binary\n"));
    lexe::util::spit(folder / "share" / "data.txt",
                     std::string_view("data\n"));

    const std::vector<std::string> files =
        lexe::gui::enumerate_entrypoints(folder);

    // Sorted, relative, forward-slash-joined; directories excluded.
    REQUIRE(files.size() == 3);
    CHECK(files == std::vector<std::string>{"bin/tool", "run.sh",
                                            "share/data.txt"});
    for (const std::string& file : files) {
        CHECK(file.find('\\') == std::string::npos);
    }
}

TEST_CASE("enumerate_entrypoints returns empty for a missing folder") {
    TempLexeHome home;
    const std::vector<std::string> files =
        lexe::gui::enumerate_entrypoints(home.path() / "no-such-folder");
    CHECK(files.empty());
}

TEST_CASE("is_reverse_dns_id matches the FORMAT-0.1 §5 shape") {
    CHECK(lexe::gui::is_reverse_dns_id("com.example.app"));
    CHECK(lexe::gui::is_reverse_dns_id("io.a.b-c.d123"));
    CHECK(lexe::gui::is_reverse_dns_id("a.b"));
    CHECK_FALSE(lexe::gui::is_reverse_dns_id(""));
    CHECK_FALSE(lexe::gui::is_reverse_dns_id("single"));
    CHECK_FALSE(lexe::gui::is_reverse_dns_id(".com.example"));
    CHECK_FALSE(lexe::gui::is_reverse_dns_id("com.example."));
    CHECK_FALSE(lexe::gui::is_reverse_dns_id("com..example"));
    CHECK_FALSE(lexe::gui::is_reverse_dns_id("com.exa_mple"));
}

// ------------------------------------------------------- Phase 2 wizard model

TEST_CASE("wizard_steps lists the seven-step default workflow in order") {
    const auto& steps = lexe::gui::wizard_steps();
    REQUIRE(steps.size() == 7);
    CHECK(steps.front().step == lexe::gui::WizardStep::Source);
    CHECK(steps[1].step == lexe::gui::WizardStep::Dependencies);
    CHECK(steps.back().step == lexe::gui::WizardStep::Build);
    CHECK(steps[3].title == "Installer"); // metadata step
}

TEST_CASE("detect_source finds the main executable, arch and dependencies") {
    TempLexeHome home;
    const fs::path folder = home.path() / "src";
    fs::create_directories(folder / "bin");

    // A bundled library and a main executable that needs it + host + missing.
    lexe::test::ElfSpec lib;
    lib.soname = "libhelper.so.1";
    lexe::test::write_elf(folder / "libhelper.so.1", lib);

    lexe::test::ElfSpec app;
    app.interp = "/lib64/ld-linux-x86-64.so.2";
    app.needed = {"libc.so.6", "libhelper.so.1", "libmissing.so.9"};
    lexe::test::write_elf(folder / "bin" / "app", app);
    // A plain data file too (not an executable).
    lexe::util::spit(folder / "data.txt", std::string_view("hello"));

    const lexe::gui::SourceDetection d = lexe::gui::detect_source(folder);
    CHECK(d.ok);
    CHECK(d.main_executable == "bin/app");
    CHECK(d.detected_arch == "x86_64");
    CHECK(contains(d.executable_type, "x86_64"));
    CHECK(d.payload_size > 0);
    CHECK(d.dependencies.count(lexe::DependencyKind::HostInterface) == 1);
    CHECK(d.dependencies.count(lexe::DependencyKind::Bundle) == 1);
    CHECK(d.dependencies.count(lexe::DependencyKind::Unresolved) == 1);
    CHECK(contains(d.summary, "dependency"));
    // Every file is offered as a candidate entrypoint.
    CHECK(std::find(d.entrypoints.begin(), d.entrypoints.end(), "bin/app") !=
          d.entrypoints.end());
}

TEST_CASE("detect_source reports no native executable for a script-only folder") {
    TempLexeHome home;
    const fs::path folder = home.path() / "scripts";
    fs::create_directories(folder);
    lexe::util::spit(folder / "run.sh", std::string_view("#!/bin/sh\necho hi\n"));

    const lexe::gui::SourceDetection d = lexe::gui::detect_source(folder);
    CHECK_FALSE(d.ok);
    CHECK(contains(d.summary, "No native executable"));
    CHECK(std::find(d.entrypoints.begin(), d.entrypoints.end(), "run.sh") !=
          d.entrypoints.end()); // still offered for manual selection
}

TEST_CASE("dependency_rows flags forbidden and unresolved dependencies") {
    lexe::DependencyReport r;
    lexe::Dependency host;
    host.soname = "libc.so.6";
    host.kind = lexe::DependencyKind::HostInterface;
    lexe::Dependency gpu;
    gpu.soname = "libGL.so.1";
    gpu.kind = lexe::DependencyKind::Forbidden;
    r.dependencies = {host, gpu};

    const auto rows = lexe::gui::dependency_rows(r);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].handling == "host-interface");
    CHECK_FALSE(rows[0].warn);
    CHECK(rows[1].handling == "forbidden");
    CHECK(rows[1].warn);
}

TEST_CASE("build_manifest_json emits categories, estimatedSize and description") {
    TempLexeHome home;
    BuilderForm form = valid_form();
    form.categories = {"Utility", "Development"};
    form.description = "A tidy little tool.";
    form.payload_size_bytes = 125829120;

    const std::string json = lexe::gui::build_manifest_json(form, kZeroKey);
    const Manifest m = Manifest::parse(json); // still a valid 0.1 manifest
    CHECK(m.install_estimated_size == 125829120);
    CHECK(m.categories == std::vector<std::string>{"Utility", "Development"});
    // description is forward-compatible metadata carried in the JSON.
    CHECK(contains(json, "A tidy little tool."));
}

// ------------------------------------------------- Core Portable build gate

// A dynamically linked x86_64 dependency report needing `glibc`, plus libc.
lexe::DependencyReport gate_source(const std::string& glibc) {
    lexe::DependencyReport r;
    r.root_info.is_elf = true;
    r.root_info.has_interpreter = true;
    r.root_info.is_dynamic = true;
    r.root_info.machine = lexe::elf::Machine::X86_64;
    r.root_info.version_needs = {glibc};
    lexe::Dependency host;
    host.soname = "libc.so.6";
    host.kind = lexe::DependencyKind::HostInterface;
    r.dependencies = {host};
    return r;
}

TEST_CASE("Core Portable gate allows a conformant source and blocks an over-ceiling one") {
    const lexe::gui::ProfileGate ok = lexe::gui::evaluate_profile_gate(
        lexe::RuntimeProfile::CorePortable, gate_source("GLIBC_2.17"));
    CHECK(ok.build_allowed);
    CHECK_FALSE(ok.blocking);
    REQUIRE(ok.core1.has_value());
    CHECK(ok.core1->verdict == lexe::Core1Verdict::Conformant);
    CHECK(contains(ok.headline, "conformant"));

    const lexe::gui::ProfileGate bad = lexe::gui::evaluate_profile_gate(
        lexe::RuntimeProfile::CorePortable, gate_source("GLIBC_2.34"));
    CHECK_FALSE(bad.build_allowed); // Build is disabled
    CHECK(bad.blocking);
    CHECK(contains(bad.headline, "NOT conformant"));
    // The exact offender is surfaced to the developer.
    bool named = false;
    for (const std::string& n : bad.notes) {
        if (contains(n, "GLIBC_2.34")) named = true;
    }
    CHECK(named);
}

TEST_CASE("Forward Runtime and Native Capture always build but carry no Core 1 gate") {
    const lexe::gui::ProfileGate fwd = lexe::gui::evaluate_profile_gate(
        lexe::RuntimeProfile::ForwardRuntime, gate_source("GLIBC_2.34"));
    CHECK(fwd.build_allowed); // an over-ceiling source still builds here
    CHECK_FALSE(fwd.blocking);
    CHECK_FALSE(fwd.core1.has_value());
    CHECK_FALSE(fwd.notes.empty()); // but it is advised to prefer Core Portable

    const lexe::gui::ProfileGate nat = lexe::gui::evaluate_profile_gate(
        lexe::RuntimeProfile::NativeCapture, gate_source("GLIBC_2.34"));
    CHECK(nat.build_allowed);
    CHECK_FALSE(nat.core1.has_value());
    CHECK(contains(nat.headline, "host-locked"));
}

// ------------------------------------------------- first-run welcome (DX8)

TEST_CASE("the welcome screen shows once, then is remembered") {
    TempLexeHome home;
    const lexe::Paths paths = lexe::Paths::detect();
    CHECK(lexe::gui::should_show_welcome(paths)); // first run
    lexe::gui::mark_welcome_seen(paths);
    CHECK_FALSE(lexe::gui::should_show_welcome(paths)); // remembered
    CHECK(fs::is_regular_file(lexe::gui::welcome_marker(paths)));
}

TEST_CASE("the welcome copy explains .lexe and points at the docs") {
    const std::string body = lexe::gui::welcome_body();
    CHECK(contains(body, ".lexe"));
    CHECK(contains(body, "docs/"));
    CHECK(body.size() > 100);
}

TEST_CASE("the profile explanation is plain-language and profile-specific") {
    const std::string core =
        lexe::gui::profile_explanation_text(lexe::RuntimeProfile::CorePortable);
    CHECK(contains(core, "Core Portable"));
    CHECK(contains(core, "Maximum"));
    CHECK(contains(core, "Tux32 Core 1")); // the guarantee is explained in place

    const std::string native =
        lexe::gui::profile_explanation_text(lexe::RuntimeProfile::NativeCapture);
    CHECK(contains(native, "Native Capture"));
    CHECK(contains(native, "Reduced"));
    CHECK_FALSE(contains(native, "Tux32 Core 1")); // no portability claim here
}

TEST_CASE("the verification note explains what packaging checks") {
    const std::string n = lexe::gui::verification_note();
    CHECK(contains(n, "signed"));
    CHECK(contains(n, "verif")); // "re-verified"
    CHECK(n.size() > 60);
}

TEST_CASE("the build progress shows meaningful stages, not logs") {
    const auto& stages = lexe::gui::build_stages();
    REQUIRE(stages.size() == 6);
    CHECK(stages.front() == "Analyzing");
    CHECK(stages[3] == "Signing");
    CHECK(stages.back() == "Finalizing");
}

TEST_CASE("an entrypoint that cannot start anything is rejected") {
    // Pointing the Builder at a folder with no executable used to pre-select
    // the first candidate alphabetically and build it: a signed package whose
    // entrypoint was a text file, reported as "Build succeeded" and
    // "Verification: PASSED" — because a package verifies against its own
    // hashes whether or not its entrypoint can run. The break only showed up
    // when a user installed it and pressed Launch.
    lexe::test::TempLexeHome home;
    const fs::path folder = home.path() / "src";
    fs::create_directories(folder);

    lexe::util::spit(folder / "data.txt", std::string_view("just some data\n"));
    CHECK_FALSE(lexe::gui::entrypoint_looks_runnable(folder, "data.txt"));

    // A shebang script counts, even without an execute bit (copies and
    // FAT/NTFS mounts routinely lose it).
    lexe::util::spit(folder / "run.sh", std::string_view("#!/bin/sh\nexec true\n"));
    CHECK(lexe::gui::entrypoint_looks_runnable(folder, "run.sh"));

    // So does an ELF binary.
    lexe::test::ElfSpec app;
    app.needed = {"libc.so.6"};
    lexe::test::write_elf(folder / "bin", app);
    CHECK(lexe::gui::entrypoint_looks_runnable(folder, "bin"));

    // Nothing selected, or something that is not there at all.
    CHECK_FALSE(lexe::gui::entrypoint_looks_runnable(folder, ""));
    CHECK_FALSE(lexe::gui::entrypoint_looks_runnable(folder, "absent"));
}

TEST_CASE("'generate a new key' never destroys the key already at that path") {
    // The Builder used to generate + write unconditionally. Its default key
    // path is ~/<app-id>.key.json, so the SECOND build of the same application
    // overwrote the first build's key — and with no authenticated key rotation
    // in 0.1, that permanently ends the ability to ship an update for that App
    // ID: the installed copy refuses the next package as "signed by a different
    // key". `lexe build` already reuses a project's existing key.json.
    lexe::test::TempLexeHome home;
    const fs::path dir = home.path() / "keys";
    fs::create_directories(dir);

    // Nothing there yet: a new key is correct.
    CHECK_FALSE(lexe::gui::should_reuse_existing_key(dir / "absent.key.json"));

    // A key IS there: it must be reused, never rewritten.
    const fs::path existing = dir / "com.example.app.key.json";
    const lexe::crypto::KeyPair original = lexe::crypto::generate_keypair();
    lexe::crypto::write_keyfile(existing, original);
    const std::string before = lexe::util::slurp_text(existing);
    CHECK(lexe::gui::should_reuse_existing_key(existing));

    // And reusing really does yield the same identity, byte-for-byte on disk.
    const lexe::crypto::KeyPair reused = lexe::crypto::read_keyfile(existing);
    CHECK(reused.public_key == original.public_key);
    CHECK(lexe::util::slurp_text(existing) == before);

    // A directory is not a key file, and an empty path is not one either.
    CHECK_FALSE(lexe::gui::should_reuse_existing_key(dir));
    CHECK_FALSE(lexe::gui::should_reuse_existing_key(fs::path{}));
}

} // TEST_SUITE("builder")

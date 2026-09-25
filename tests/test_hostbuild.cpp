// hostbuild tests — portable code and host-ISA compilation (Definitive
// Architecture §5/§7, FORMAT-0.1 §5.8 and §6.9).
//
// The architecture attaches four properties to "the destination machine
// compiles it", and this file is organised around them because any one of them
// missing turns the feature into remote code execution with extra steps:
//
//   1. ADMIN COMPILE APPROVAL gates the OPERATION;
//   2. the build runs UNPRIVILEGED and ISOLATED;
//   3. the OUTPUT IS VERIFIED as a host-ISA native executable before use;
//   4. approval authorizes the operation and grants NO privilege.
//
// The policy half (1, 3 and the shape of 2) is pure and runs on every platform.
// The half that actually compiles something needs a real sandbox and a real
// toolchain, and says so when the host has neither.
//
// Every test case constructs lexe::test::TempLexeHome first.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/hostbuild.hpp"
#include "core/installer.hpp"
#include "core/isolation.hpp"
#include "core/launcher.hpp"
#include "core/manifest.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;
using lexe::test::TempLexeHome;

namespace {

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

Manifest portable_manifest(BuildSystem system = BuildSystem::Command) {
    Manifest m;
    m.lexe_version = "0.1";
    m.id = "com.example.portable";
    m.name = "Portable";
    m.version = "1.0.0";
    m.publisher_name = "P";
    m.publisher_public_key =
        "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    m.application_type = "portable";
    m.application_kind = ApplicationType::Portable;
    m.architectures = {"x86_64", "aarch64"};
    m.entrypoint_executable = "bin/app";
    m.install_mode = "bundled";
    m.build.system = system;
    m.build.source_dir = "src";
    if (system == BuildSystem::Command) {
        m.build.command = {"cc", "-o", "bin/app", "src/main.c"};
    }
    m.build.toolchain = {"cc"};
    return m;
}

/// An isolation request shaped like a build, for the pure-plan cases.
IsolationRequest build_request(const fs::path& tree) {
    IsolationRequest req;
    req.app_id = "com.example.portable";
    req.app_root = tree;
    req.entrypoint = "make";
    req.data_root = tree.parent_path() / "scratch" / "home";
    req.cache_root = tree.parent_path() / "scratch" / "cache";
    req.build = true;
    return req;
}

IsolationCapabilities full_capabilities() {
    IsolationCapabilities caps;
    caps.status = CapabilityStatus::Available;
    caps.backend_present = true;
    caps.user_namespaces = true;
    caps.network_namespaces = true;
    caps.bind_mounts = true;
    return caps;
}

const BindMount* find_bind(const IsolationPlan& plan, const std::string& host) {
    for (const BindMount& b : plan.binds) {
        if (b.host == host) return &b;
    }
    return nullptr;
}

/// True when this host can actually compile and sandbox. Both halves are
/// needed for the cases that build something for real.
bool can_build_here(const Paths& paths) {
    if (!lexe::test::have_native_compiler()) return false;
    const std::unique_ptr<IsolationBackend> backend =
        make_isolation_backend(paths);
    return backend->capabilities().status == CapabilityStatus::Available;
}

} // namespace

TEST_SUITE("hostbuild") {

// ---------------------------------------------------------------------------
// Property 1: approval gates the operation.
// ---------------------------------------------------------------------------

TEST_CASE("without approval nothing is compiled, and the reason says so") {
    TempLexeHome home;
    const Paths paths = Paths::detect();

    CompileRequest request;
    request.manifest = portable_manifest();
    request.build_tree = home.path() / "tree";
    request.scratch_dir = home.path() / "scratch";
    fs::create_directories(request.build_tree);
    // request.approval is default-constructed: NOT granted. Nothing compiles
    // by omission.

    const CompileResult result = compile_for_host(paths, request);
    CHECK_FALSE(result.ok);
    CHECK(result.outcome == CompileOutcome::NotApproved);
    CHECK(result.commands_run.empty()); // it did not get as far as a command
    CHECK(contains(result.failure, "not approved"));
    CHECK(contains(result.hint, "--approve-compile"));
    // …and it says what approval does NOT do, because that is the part a user
    // has every reason to be suspicious about.
    CHECK(contains(result.hint, "grants the build no privileges"));
}

TEST_CASE("an approval records who gave it and when") {
    TempLexeHome home;
    const CompileApproval approval = CompileApproval::grant();
    CHECK(approval.granted);
    // There is no privileged administrator in a per-user installation, and the
    // record says exactly whose decision this was rather than implying one.
    CHECK(approval.authority == "user");
    CHECK_FALSE(approval.approved_at.empty());
}

// ---------------------------------------------------------------------------
// Property 2: the build runs unprivileged and isolated — and property 4, that
// approval buys the build no authority the application would not have had.
// ---------------------------------------------------------------------------

TEST_CASE("a build plan is the launch sandbox with a writable tree") {
    TempLexeHome home;
    const fs::path tree = home.path() / "staging" / "1.0.0";
    fs::create_directories(tree);

    const IsolationPlan plan =
        build_plan(build_request(tree), full_capabilities());

    // The build tree is writable — a build that cannot write its outputs is
    // not a build — and that is REPORTED, not quietly claimed as enforced.
    const BindMount* root = find_bind(plan, tree.generic_string());
    REQUIRE(root != nullptr);
    CHECK_FALSE(root->read_only);
    CHECK(plan.controls.at(IsolationControl::AppRootReadOnly) ==
          ControlState::NotApplicable);

    // Everything else is exactly the launcher's sandbox.
    CHECK(plan.controls.at(IsolationControl::HomeHidden) ==
          ControlState::Enforced);
    CHECK(plan.controls.at(IsolationControl::NetworkDenied) ==
          ControlState::Enforced);
    CHECK(plan.controls.at(IsolationControl::DisplayIsolated) ==
          ControlState::Enforced);
    CHECK(plan.controls.at(IsolationControl::PidNamespace) ==
          ControlState::Enforced);
    CHECK(plan.controls.at(IsolationControl::NoNewPrivileges) ==
          ControlState::Enforced);
    CHECK(plan.controls.at(IsolationControl::EnvironmentSanitized) ==
          ControlState::Enforced);

    CHECK_FALSE(plan.network_shared);
    CHECK(plan.working_dir == tree.generic_string());
    // A failed build has to be explainable, so its output is captured rather
    // than sent to whatever terminal — possibly none — install ran from.
    CHECK(plan.capture_output);
}

TEST_CASE("a build never gets the network, whatever the permissions say") {
    TempLexeHome home;
    const fs::path tree = home.path() / "staging" / "1.0.0";
    fs::create_directories(tree);

    IsolationRequest req = build_request(tree);
    req.network_allowed = true; // the application may have the permission…

    const IsolationPlan plan = build_plan(req, full_capabilities());
    // …but its BUILD does not. A build that downloads is fetching unsigned
    // code onto the machine at install time, behind a signature that says
    // nothing about what was fetched.
    CHECK_FALSE(plan.network_shared);
    CHECK(plan.controls.at(IsolationControl::NetworkDenied) ==
          ControlState::Enforced);
    CHECK(find_bind(plan, "/etc/resolv.conf") == nullptr);
}

TEST_CASE("a build never gets the display, whatever the launch mode says") {
    TempLexeHome home;
    const fs::path tree = home.path() / "staging" / "1.0.0";
    fs::create_directories(tree);

    IsolationRequest req = build_request(tree);
    req.gui = true;
    req.inherited_env["WAYLAND_DISPLAY"] = "wayland-0";
    req.inherited_env["XDG_RUNTIME_DIR"] = "/run/user/1000";
    req.inherited_env["DISPLAY"] = ":0";

    const IsolationPlan plan = build_plan(req, full_capabilities());
    CHECK(plan.controls.at(IsolationControl::DisplayIsolated) ==
          ControlState::Enforced);
    CHECK(find_bind(plan, "/tmp/.X11-unix/X0") == nullptr);
    CHECK(plan.env.count("WAYLAND_DISPLAY") == 0);
    CHECK(plan.env.count("DISPLAY") == 0);
    CHECK(plan.env.count("XDG_RUNTIME_DIR") == 0);
    // The build environment is minimal and stable, so a compiler diagnostic
    // that ends up in an error record reads the same on every machine.
    CHECK(plan.env.at("LC_ALL") == "C");
    CHECK(plan.env.at("LEXE_BUILD") == "1");
}

TEST_CASE("FAIL CLOSED: no network namespace means no build") {
    TempLexeHome home;
    const fs::path tree = home.path() / "staging" / "1.0.0";
    fs::create_directories(tree);

    IsolationCapabilities caps = full_capabilities();
    caps.network_namespaces = false;

    // Not "build it with the network reachable, this once".
    CHECK_THROWS_AS(build_plan(build_request(tree), caps), IsolationError);
}

TEST_CASE("no isolation backend means no build") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    // Point the backend at a bubblewrap that is not there; the launcher uses
    // the same override to prove it never runs an app unconfined.
    lexe::util::set_env("LEXE_BWRAP", (home.path() / "no-such-bwrap").string());

    CompileRequest request;
    request.manifest = portable_manifest();
    request.build_tree = home.path() / "tree";
    request.scratch_dir = home.path() / "scratch";
    fs::create_directories(request.build_tree);
    request.approval = CompileApproval::grant();

    const CompileResult result = compile_for_host(paths, request);
    lexe::util::unset_env("LEXE_BWRAP");

    CHECK_FALSE(result.ok);
    CHECK(result.outcome == CompileOutcome::NoSandbox);
    CHECK(result.commands_run.empty());
    CHECK(contains(result.failure, "refusing to build unconfined"));
}

// ---------------------------------------------------------------------------
// The host is checked BEFORE anything runs.
// ---------------------------------------------------------------------------

TEST_CASE("the declared toolchain is probed against this host") {
    TempLexeHome home;
    BuildRecipe recipe;
    recipe.toolchain = {"cc", "definitely-not-a-real-compiler-9e3a"};

    const ToolchainReport report = probe_toolchain(recipe);
    CHECK_FALSE(report.complete);
    REQUIRE(report.entries.size() == 2);
    CHECK(report.missing ==
          std::vector<std::string>{"definitely-not-a-real-compiler-9e3a"});
    // The summary names the missing tool, because "cannot build here" without
    // saying what is missing is not an answer anybody can act on.
    CHECK(contains(report.summary, "definitely-not-a-real-compiler-9e3a"));
    CHECK(contains(report.summary, "does not substitute a different toolchain"));
}

TEST_CASE("a missing tool stops the build before it starts") {
    TempLexeHome home;
    const Paths paths = Paths::detect();

    Manifest manifest = portable_manifest();
    manifest.build.toolchain = {"definitely-not-a-real-compiler-9e3a"};

    CompileRequest request;
    request.manifest = manifest;
    request.build_tree = home.path() / "tree";
    request.scratch_dir = home.path() / "scratch";
    fs::create_directories(request.build_tree);
    request.approval = CompileApproval::grant();

    const CompileResult result = compile_for_host(paths, request);
    CHECK_FALSE(result.ok);
    CHECK(result.outcome == CompileOutcome::ToolchainMissing);
    CHECK(result.commands_run.empty());
}

// ---------------------------------------------------------------------------
// What a recipe actually runs is inspectable without running it.
// ---------------------------------------------------------------------------

TEST_CASE("each build system resolves to an exact argv") {
    TempLexeHome home;

    Manifest make = portable_manifest(BuildSystem::Make);
    const auto make_commands = build_commands(make);
    REQUIRE(make_commands.size() == 1);
    CHECK(make_commands[0] == std::vector<std::string>{"make", "-C", "src"});

    Manifest cmake = portable_manifest(BuildSystem::CMake);
    const auto cmake_commands = build_commands(cmake);
    REQUIRE(cmake_commands.size() == 2);
    // Configured OUT of tree, into a directory the runtime names: a package
    // does not get to choose where its build artifacts land.
    CHECK(cmake_commands[0][0] == "cmake");
    CHECK(cmake_commands[0][4] == "lexe-build");
    CHECK(cmake_commands[1] ==
          std::vector<std::string>{"cmake", "--build", "lexe-build"});

    Manifest command = portable_manifest(BuildSystem::Command);
    const auto own = build_commands(command);
    REQUIRE(own.size() == 1);
    CHECK(own[0] == command.build.command);
}

// ---------------------------------------------------------------------------
// The build record — the compiled entrypoint's only integrity anchor.
// ---------------------------------------------------------------------------

TEST_CASE("a build record round-trips, and an unknown schema is refused") {
    TempLexeHome home;
    BuildRecord record;
    record.application_id = "com.example.portable";
    record.application_version = "1.0.0";
    record.build_system = "command";
    record.source_dir = "src";
    record.host_isa = "x86_64";
    record.built_at = "2026-09-25T00:00:00Z";
    record.runtime_version = "0.1.0-alpha";
    record.approval = CompileApproval::grant();
    record.toolchain = {{"cc", "/usr/bin/cc", true}};
    record.products["payload/bin/app"] = std::string(64, 'a');

    const BuildRecord again = BuildRecord::from_json(record.to_json());
    CHECK(again.application_id == record.application_id);
    CHECK(again.build_system == "command");
    CHECK(again.host_isa == "x86_64");
    CHECK(again.approval.granted);
    CHECK(again.approval.approved_by == record.approval.approved_by);
    REQUIRE(again.toolchain.size() == 1);
    CHECK(again.toolchain[0].name == "cc");
    CHECK(again.products.at("payload/bin/app") == std::string(64, 'a'));

    record.save(home.path());
    const std::optional<BuildRecord> loaded = BuildRecord::load(home.path());
    REQUIRE(loaded.has_value());
    CHECK(loaded->products == record.products);

    // A native package has none, and that is not an error.
    CHECK_FALSE(BuildRecord::load(home.path() / "elsewhere").has_value());

    std::string tampered = record.to_json();
    const std::size_t at = tampered.find("lexe.build/1");
    REQUIRE(at != std::string::npos);
    tampered.replace(at, 12, "lexe.build/9");
    CHECK_THROWS_AS(BuildRecord::from_json(tampered), Error);
}

// ---------------------------------------------------------------------------
// The whole path, for real: install compiles, the result is verified, the
// compiled binary is protected exactly like an extracted one.
// ---------------------------------------------------------------------------

TEST_CASE("installing a portable package compiles it for this host") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!can_build_here(paths)) {
        MESSAGE("SKIP: this host has no C compiler and/or no usable sandbox");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = test::make_portable_package(home.path(), key);

    Installer installer(paths);

    // 1. Without approval: refused, and nothing is installed.
    InstallOptions plain;
    CHECK_THROWS_AS(installer.install(pkg, plain), PermissionError);
    Registry registry(paths);
    CHECK_THROWS_AS(registry.read_record("com.example.portable"), NotFoundError);

    // 2. With approval: installed, and what landed is a host-ISA executable
    //    the package never contained.
    InstallOptions approved;
    approved.approve_compile = true;
    const InstallResult result = installer.install(pkg, approved);
    CHECK(result.id == "com.example.portable");

    const fs::path entry =
        registry.version_dir(result.id, result.version) / "bin" / "app";
    REQUIRE(fs::is_regular_file(entry));
    const elf::ElfInfo info = elf::read(entry);
    CHECK(info.is_elf);
    CHECK(info.arch() == host_architecture());

    // 3. The build is recorded: what was approved, by whom, with which tools,
    //    and what it produced.
    const std::optional<BuildRecord> record =
        BuildRecord::load(registry.meta_dir(result.id, result.version));
    REQUIRE(record.has_value());
    CHECK(record->approval.granted);
    CHECK(record->host_isa == host_architecture());
    CHECK(record->application_version == result.version);
    REQUIRE(record->products.count("payload/bin/app") == 1);
    CHECK(record->products.at("payload/bin/app") ==
          crypto::sha256_file_hex(entry));

    // 4. And it runs — natively, because that is what it now is.
    CHECK(run_app(paths, result.id, {}) == 0);
}

TEST_CASE("a compiled entrypoint is tamper-protected like an extracted one") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!can_build_here(paths)) {
        MESSAGE("SKIP: this host has no C compiler and/or no usable sandbox");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = test::make_portable_package(home.path(), key);

    Installer installer(paths);
    InstallOptions approved;
    approved.approve_compile = true;
    const InstallResult result = installer.install(pkg, approved);
    Registry registry(paths);
    const fs::path entry =
        registry.version_dir(result.id, result.version) / "bin" / "app";

    // The compiled entrypoint is not in the package's signed hashes.json — it
    // did not exist when the package was signed. If the recorded product hash
    // were not consulted, compiled binaries would be the one kind of payload
    // this runtime never noticed being replaced.
    {
        std::vector<std::uint8_t> bytes = util::slurp(entry);
        REQUIRE(bytes.size() > 0x400);
        bytes[0x400] = static_cast<std::uint8_t>(bytes[0x400] ^ 0xFF);
        util::spit(entry, bytes);
    }
    CHECK_THROWS_AS(run_app(paths, result.id, {}), LaunchError);

    // Repairing it means BUILDING it again, so it needs the same approval the
    // install did — a repair command must not silently compile code.
    CHECK_THROWS_AS(installer.repair(result.id), PermissionError);

    RepairOptions repair_opts;
    repair_opts.approve_compile = true;
    const RepairReport repaired = installer.repair(result.id, pkg, repair_opts);
    CHECK(repaired.ok);
    CHECK(run_app(paths, result.id, {}) == 0);
}

TEST_CASE("FAIL CLOSED: a portable app with no build record does not launch") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!can_build_here(paths)) {
        MESSAGE("SKIP: this host has no C compiler and/or no usable sandbox");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = test::make_portable_package(home.path(), key);

    Installer installer(paths);
    InstallOptions approved;
    approved.approve_compile = true;
    const InstallResult result = installer.install(pkg, approved);

    Registry registry(paths);
    fs::remove(registry.meta_dir(result.id, result.version) / "build.json");

    // Losing the record means losing the only statement of what the compiled
    // entrypoint should hash to. An unverifiable binary is not one to run.
    CHECK_THROWS_AS(run_app(paths, result.id, {}), LaunchError);
}

// ---------------------------------------------------------------------------
// Property 3: the output is verified. A build that exits 0 has proved nothing.
// ---------------------------------------------------------------------------

TEST_CASE("a build that produces nothing is an install failure") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!can_build_here(paths)) {
        MESSAGE("SKIP: this host has no C compiler and/or no usable sandbox");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    test::PortableAppSpec spec;
    spec.id = "com.example.nothing";
    spec.command = {"true"}; // exits 0, builds nothing
    spec.toolchain = {"true"};
    const fs::path pkg = test::make_portable_package(home.path(), key, spec);

    Installer installer(paths);
    InstallOptions approved;
    approved.approve_compile = true;
    CHECK_THROWS_AS(installer.install(pkg, approved), CompileError);

    // Nothing was promoted: the failure happened inside the staging tree.
    Registry registry(paths);
    CHECK_THROWS_AS(registry.read_record(spec.id), NotFoundError);
}

TEST_CASE("a build that produces something that is not an executable is too") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!can_build_here(paths)) {
        MESSAGE("SKIP: this host has no C compiler and/or no usable sandbox");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    test::PortableAppSpec spec;
    spec.id = "com.example.notelf";
    // A "build" that copies a text file into place. The recipe succeeds; the
    // result is not a program, and only checking the output catches it.
    spec.command = {"cp", "src/README", "bin/app"};
    spec.toolchain = {"cp"};
    const fs::path pkg = test::make_portable_package(home.path(), key, spec);

    Installer installer(paths);
    InstallOptions approved;
    approved.approve_compile = true;
    try {
        installer.install(pkg, approved);
        FAIL("expected the install to be refused");
    } catch (const CompileError& e) {
        CHECK(contains(e.what(), "not an ELF object"));
    }
}

TEST_CASE("a failed build leaves a diagnostic carrying the build's output") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!can_build_here(paths)) {
        MESSAGE("SKIP: this host has no C compiler and/or no usable sandbox");
        return;
    }
    const crypto::KeyPair key = test::make_keypair();
    test::PortableAppSpec spec;
    spec.id = "com.example.brokenbuild";
    spec.command = {"cc", "-o", "bin/app", "src/does-not-exist.c"};
    const fs::path pkg = test::make_portable_package(home.path(), key, spec);

    Installer installer(paths);
    InstallOptions approved;
    approved.approve_compile = true;
    CHECK_THROWS_AS(installer.install(pkg, approved), CompileError);

    // The compiler's own words are what make this diagnosable, and the person
    // installing may have had no terminal to see them on.
    const ErrorStore errors(paths);
    const std::optional<ErrorRecord> latest = errors.latest(spec.id);
    REQUIRE(latest.has_value());
    CHECK(latest->stage == FailureStage::Compile);
    CHECK_FALSE(latest->stderr_path.empty());
    CHECK(contains(util::slurp_text(latest->stderr_path), "does-not-exist.c"));
}

// ---------------------------------------------------------------------------
// A portable package resolves to the native chain — that is the whole point.
// ---------------------------------------------------------------------------

TEST_CASE("a portable package resolves to native, strict resolver included") {
    TempLexeHome home;
    Manifest manifest = portable_manifest();
    HostFacts host;
    host.isa = "x86_64";

    const ChainResolution normal =
        resolve_chain(manifest, AppConfig{}, host, ProviderSet{});
    REQUIRE(normal.ok);
    CHECK(normal.chain.native);
    CHECK(normal.chain.argv_prefix.empty());

    // Mission-critical requires Linux-native AND host-ISA-native AND verified.
    // A package compiled here at install time is all three — a compiler ran,
    // and its output was checked before anything was promoted.
    manifest.mission_critical = true;
    manifest.allowed_chains = {"native"};
    const ChainResolution strict =
        resolve_chain(manifest, AppConfig{}, host, ProviderSet{});
    CHECK(strict.strict_resolver);
    REQUIRE(strict.ok);
    CHECK(strict.chain.native);
    CHECK(strict.alternatives.empty());
}

} // TEST_SUITE("hostbuild")

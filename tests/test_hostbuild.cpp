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

#include "lexe/package/crypto.hpp"
#include "lexe/base/error.hpp"
#include "lexe/runtime/hostbuild.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/sandbox/isolation.hpp"
#include "lexe/runtime/launcher.hpp"
#include "lexe/package/manifest.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/base/util.hpp"
#include "lexe/verify/verify.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;
using lexe::test::TempLexeHome;

namespace {

/// The value of a `KEY=value` line anywhere in `out`, or "" if absent.
///
/// Build drivers interleave their own chatter with the recipe's output --
/// `make -C` announces the directory it entered before the recipe runs at all
/// -- so a test that wants a recipe's answer must ask for it by name rather
/// than by position. Returns "" rather than throwing so the caller can decide
/// how loud an absence is; every caller here treats it as fatal.
std::string marked_value(const std::string& out, const std::string& key) {
    const std::string needle = key + "=";
    // Anchored to a line start, so a key mentioned inside some other line
    // (a path, an echoed command) cannot be mistaken for the marker.
    std::size_t pos = out.compare(0, needle.size(), needle) == 0
                          ? 0
                          : out.find("\n" + needle);
    if (pos == std::string::npos) return {};
    if (pos != 0) ++pos; // step over the newline
    pos += needle.size();
    const std::size_t end = out.find('\n', pos);
    std::string value =
        out.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    while (!value.empty() && (value.back() == '\r' || value.back() == ' ')) {
        value.pop_back();
    }
    return value;
}

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
// `build.sourceDir` is not a working directory, and the drivers disagree about
// it. The schema used to say the build "sees this directory and nothing else of
// the package"; neither half was true of any driver. These two cases pin what
// IS true, and they are written to fail if anyone makes them agree by accident.
//
// The pair is deliberate. The first is pure and asserts the DISTINCTION between
// drivers — a single-driver test would pass unchanged if all three were
// flattened to the same answer, which is exactly the defect. The second is the
// independent observer: it runs a real build in the sandbox and takes the
// directory from the BUILD's own `pwd`, not from anything the runtime says
// about itself. If the runtime's answer and the build's answer ever diverge,
// the second fails — and neither test can be satisfied by machinery reporting
// on itself.
// ---------------------------------------------------------------------------

TEST_CASE("sourceDir reaches the three drivers differently, and the note says "
          "which") {
    TempLexeHome home;

    const Manifest make = portable_manifest(BuildSystem::Make);
    const Manifest cmake = portable_manifest(BuildSystem::CMake);
    const Manifest command = portable_manifest(BuildSystem::Command);

    // The distinction, stated as a distinction: `make -C src` chdirs make, the
    // other two do not move at all.
    CHECK(build_working_subdir(make) == "src");
    CHECK(build_working_subdir(cmake).empty());
    CHECK(build_working_subdir(command).empty());
    CHECK(build_working_subdir(make) != build_working_subdir(command));

    // And the publisher-facing note distinguishes them too — the `command`
    // case in particular has to name the payload root, because "my configure
    // script is not found and it is right there in the package" is the failure
    // this note exists to answer.
    CHECK(contains(build_layout_note(command), "PAYLOAD ROOT"));
    CHECK(contains(build_layout_note(command), "not applied to it at all"));
    CHECK(contains(build_layout_note(make), "make -C src"));
    CHECK(build_layout_note(make) != build_layout_note(command));
    CHECK(build_layout_note(cmake) != build_layout_note(command));
}

TEST_CASE("the directory a build really runs in is the one the runtime claims, "
          "and sourceDir confines nothing") {
    TempLexeHome home;
    const Paths paths = Paths::detect();
    const std::unique_ptr<IsolationBackend> backend =
        make_isolation_backend(paths);
    if (backend->capabilities().status != CapabilityStatus::Available) {
        MESSAGE("SKIP: no usable sandbox on this host");
        return;
    }

    // One tree, two recipes over it, differing ONLY in build.system.
    //
    // OUTSIDE-SOURCEDIR sits at the payload root, outside `src`. Each recipe
    // reads it by a path relative to its own working directory, so a success
    // is evidence about BOTH facts at once: where the build stands, and that
    // the package outside sourceDir is reachable from there.
    const auto run = [&](BuildSystem system) {
        Manifest m = portable_manifest(system);
        m.build.toolchain = {system == BuildSystem::Make ? "make" : "sh"};
        const std::string tag =
            system == BuildSystem::Make ? "make" : "command";
        const fs::path tree = home.path() / ("cwd-" + tag) / "version";
        fs::create_directories(tree / "src");
        util::spit(tree / "OUTSIDE-SOURCEDIR",
                   std::string_view("payload root marker\n"));
        if (system == BuildSystem::Make) {
            // `make -C src` runs these rules inside src, so the marker is one
            // level up from where this recipe stands.
            // `$$(pwd)` because make eats one `$`; the shell then runs pwd.
            util::spit(tree / "src" / "Makefile",
                       std::string_view("all:\n\t@echo \"PWD_MARK=$$(pwd)\"\n"
                                        "\t@cat ../OUTSIDE-SOURCEDIR\n"));
            // A SECOND, equally valid Makefile at the payload root.
            //
            // Nothing invokes it while `make -C src` is correct, and that is
            // the point: if the driver ever stopped passing `-C`, make would
            // find THIS one and the build would still succeed -- reporting the
            // payload root. Without it, a driver that lost `-C` fails with
            // "No targets specified and no makefile found", which is a loud
            // and obviously different symptom; with it, the failure is the
            // quiet one the relative-position check below is here to catch.
            //
            // So this file exists to make the dangerous case REACHABLE. A
            // fixture that only permits the loud failure cannot demonstrate
            // that the quiet one is detected.
            util::spit(tree / "Makefile",
                       std::string_view("all:\n\t@echo \"PWD_MARK=$$(pwd)\"\n"
                                        "\t@cat OUTSIDE-SOURCEDIR\n"));
        } else {
            m.build.command = {"sh", "-c",
                               "echo \"PWD_MARK=$(pwd)\"; cat OUTSIDE-SOURCEDIR"};
        }
        CompileRequest req;
        req.manifest = m;
        req.build_tree = tree;
        req.scratch_dir = home.path() / ("scratch-" + tag);
        req.approval = CompileApproval::grant();
        return std::tuple{m, tree, compile_for_host(paths, req)};
    };

    std::string observed[2];
    fs::path trees[2];
    for (int i = 0; i < 2; ++i) {
        const BuildSystem system =
            i == 0 ? BuildSystem::Command : BuildSystem::Make;
        const auto [m, tree, result] = run(system);
        trees[i] = tree;
        if (result.outcome == CompileOutcome::ToolchainMissing) {
            MESSAGE("SKIP: this host lacks sh/make");
            return;
        }
        // The commands run and print; nothing produces bin/app, so the compile
        // is expected to stop at output verification. That is the point at
        // which the build's own stdout is already captured.
        REQUIRE(result.outcome == CompileOutcome::OutputNotAccepted);

        // Read the MARKED line, not the first one.
        //
        // The first version of this observer took `out.substr(0, first \n)`,
        // which is correct for `sh` and wrong for `make`: invoked as
        // `make -C src`, GNU make announces
        //
        //     make: Entering directory '/.../version/src'
        //
        // BEFORE the recipe produces anything, so line 1 was make's chatter.
        // The comparison then read `"src'" == "src"` and the test failed for a
        // reason that had nothing to do with the property under test. A test
        // that fails for the wrong reason is no better evidence than one that
        // passes for the wrong reason -- it just wastes the failure.
        //
        // Suppressing the chatter with --no-print-directory was the other
        // option and is the wrong one: that changes the PRODUCT to suit the
        // observer. The recipe emits a key nothing else in the stream uses,
        // and the observer finds it by name.
        const std::string out = result.stdout_text;
        observed[i] = marked_value(out, "PWD_MARK");

        // An absent marker must fail LOUDLY. Left as an empty string, the two
        // drivers would compare equal to each other and to a `claimed` path
        // that is never empty -- so a broken recipe would look like a
        // disagreement about working directories rather than like a broken
        // recipe. REQUIRE, not CHECK: nothing below this line means anything
        // if the build did not report where it stood.
        REQUIRE_MESSAGE(!observed[i].empty(),
                        "the build produced no PWD_MARK= line; its stdout was: "
                            << out);

        // 1. The runtime's claim, checked against the build's own answer.
        const std::string subdir = build_working_subdir(m);
        const fs::path claimed =
            subdir.empty() ? tree : tree / fs::path(subdir);
        CHECK(fs::path(observed[i]).generic_string() ==
              fs::path(claimed).generic_string());

        // 2. "and nothing else of the package" — retracted, and here is why:
        //    a payload file OUTSIDE sourceDir was read by the build, under
        //    both drivers.
        CHECK(contains(out, "payload root marker"));
    }

    // 3. The asymmetry itself, stated WITHOUT asking the product where it
    //    thinks it put the build.
    //
    //    Assertion 1 compares the product's behaviour against the product's
    //    own `build_working_subdir()`. That is worth having and it is not
    //    independent: both sides come from the same source, so if that helper
    //    and the driver were wrong in the same direction, assertion 1 would
    //    agree with the defect. docs/TESTING.md §1.5 -- a test written from the
    //    implementation agrees with the implementation by construction. This
    //    block therefore uses only paths the TEST itself created.
    //
    //    The earlier form compared observed[0] and observed[1] to each other:
    //
    //        CHECK(fs::path(observed[1]).parent_path() == fs::path(observed[0]));
    //
    //    The two drivers deliberately run in SEPARATE trees (`cwd-command` and
    //    `cwd-make`), so those paths share no ancestor and that check could
    //    never have passed, whatever the product did. It was a second defect
    //    in the observer, hidden behind the first: the `make: Entering
    //    directory` parsing bug failed earlier and masked it.
    //
    //    The comparable quantity is each driver's position RELATIVE to its own
    //    payload root.
    const fs::path rel_command =
        fs::path(observed[0]).lexically_relative(trees[0]);
    const fs::path rel_make =
        fs::path(observed[1]).lexically_relative(trees[1]);

    CHECK(rel_command == fs::path("."));  // `command`: stands at the payload root
    CHECK(rel_make == fs::path("src"));   // `make -C`: one level in, at sourceDir
    CHECK(rel_command != rel_make);       // and the asymmetry is real
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

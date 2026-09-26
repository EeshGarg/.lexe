// Tests for the Definitive Architecture's execution model: package roles
// (§15.1), mission-critical policy (§6), the normal compatibility resolver
// (§8), per-application user overrides (§10), structured diagnostics (§9) and
// launch references (§15.1).
//
// The point of most of these is that three inputs must stay SEPARATE and must
// never be collapsed into one another:
//
//   the signed package policy   — what the publisher permits
//   the per-user override       — what this machine prefers
//   the probed host reality     — what is actually installed here
//
// A user preference must never be able to grant an execution method the
// publisher forbade, and mission-critical policy must never be reachable by
// any of the three.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/state/appconfig.hpp"
#include "lexe/package/crypto.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/integration/integration.hpp"
#include "lexe/diagnostics/diagnostics.hpp"
#include "lexe/base/error.hpp"
#include "lexe/runtime/execpolicy.hpp"
#include "lexe/runtime/launchref.hpp"
#include "lexe/package/manifest.hpp"
#include "lexe/package/package.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/base/util.hpp"
#include "lexe/verify/verify.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

using namespace lexe;

namespace {

struct TempWorkDir {
    fs::path dir;
    TempWorkDir() : dir(test::unique_temp_dir("lexe-exec-arch-")) {
        fs::create_directories(dir);
    }
    ~TempWorkDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    TempWorkDir(const TempWorkDir&) = delete;
    TempWorkDir& operator=(const TempWorkDir&) = delete;
};

/// A minimal valid application manifest as JSON text, with `extra` merged in.
std::string app_manifest_json(const nlohmann::json& extra = {}) {
    nlohmann::json doc = {
        {"lexeVersion", "0.1"},
        {"id", "com.example.app"},
        {"name", "App"},
        {"version", "1.0.0"},
        {"publisher",
         {{"name", "Publisher"},
          {"publicKey",
           "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}},
        {"applicationType", "native"},
        {"architectures", nlohmann::json::array({"x86_64"})},
        {"entrypoint", {{"executable", "bin/app"}}},
        {"install", {{"scope", "user"}, {"mode", "bundled"}}},
    };
    for (auto it = extra.begin(); it != extra.end(); ++it) {
        doc[it.key()] = it.value();
    }
    return doc.dump(2);
}

/// A manifest value for resolver tests (parsing is exercised separately).
Manifest native_manifest(bool mission_critical,
                         std::vector<std::string> chains) {
    Manifest m;
    m.lexe_version = "0.1";
    m.id = "com.example.app";
    m.name = "App";
    m.version = "1.0.0";
    m.role = PackageRole::Application;
    m.application_type = "native";
    m.architectures = {"x86_64"};
    m.entrypoint_executable = "bin/app";
    m.install_mode = "bundled";
    m.mission_critical = mission_critical;
    m.allowed_chains = std::move(chains);
    return m;
}

/// A provider set with exactly the named providers marked available, so
/// resolver behaviour is deterministic regardless of what this host has.
ProviderSet fake_providers(const std::vector<std::string>& available) {
    ProviderSet set = probe_providers();
    for (Provider& provider : set.providers) {
        const bool on = std::find(available.begin(), available.end(),
                                  provider.id) != available.end();
        provider.available = on;
        provider.executable = on ? ("/usr/bin/" + provider.id) : "";
        provider.detail = on ? "test: available" : "test: absent";
    }
    return set;
}

HostFacts host_x86() {
    HostFacts host;
    host.isa = "x86_64";
    host.os = "linux";
    return host;
}

bool has_chain(const std::vector<ExecutionChain>& chains,
               const std::string& id) {
    return std::any_of(chains.begin(), chains.end(),
                       [&](const ExecutionChain& c) { return c.id == id; });
}

} // namespace

TEST_SUITE("execution-architecture") {

// ----------------------------------------------------------- package role

TEST_CASE("the signed manifest role decides which fields are required") {
    // §15.1: install and launch artifacts share the container and MIME type;
    // the ROLE in the signed manifest is what distinguishes them. That means
    // the two roles must be structurally distinct, not merely differently
    // labelled — otherwise renaming a file could change what it does.
    SUBCASE("role defaults to application when absent") {
        const Manifest m = Manifest::parse(app_manifest_json());
        CHECK(m.role == PackageRole::Application);
    }
    SUBCASE("an unknown role is rejected") {
        CHECK_THROWS_AS(Manifest::parse(app_manifest_json({{"role", "sneaky"}})),
                        VerificationError);
    }
    SUBCASE("a launch reference parses and names its target") {
        const nlohmann::json doc = {
            {"lexeVersion", "0.1"},
            {"id", "org.lexe.launch"},
            {"name", "App"},
            {"version", "1.0.0"},
            {"role", "launch"},
            {"publisher",
             {{"name", "Local"},
              {"publicKey",
               "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}},
            {"launch", {{"applicationId", "com.example.app"}}},
        };
        const Manifest m = Manifest::parse(doc.dump(2));
        CHECK(m.role == PackageRole::Launch);
        CHECK(m.launch_application_id == "com.example.app");
    }
    SUBCASE("a launch reference may not carry application fields") {
        for (const char* field :
             {"applicationType", "architectures", "entrypoint", "install"}) {
            nlohmann::json doc = {
                {"lexeVersion", "0.1"},
                {"id", "org.lexe.launch"},
                {"name", "App"},
                {"version", "1.0.0"},
                {"role", "launch"},
                {"publisher",
                 {{"name", "Local"},
                  {"publicKey",
                   "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}},
                {"launch", {{"applicationId", "com.example.app"}}},
            };
            doc[field] = "x";
            CAPTURE(field);
            CHECK_THROWS_AS(Manifest::parse(doc.dump(2)), VerificationError);
        }
    }
    SUBCASE("a launch reference must name an application") {
        const nlohmann::json doc = {
            {"lexeVersion", "0.1"},
            {"id", "org.lexe.launch"},
            {"name", "App"},
            {"version", "1.0.0"},
            {"role", "launch"},
            {"publisher",
             {{"name", "Local"},
              {"publicKey",
               "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}},
        };
        CHECK_THROWS_AS(Manifest::parse(doc.dump(2)), VerificationError);
    }
    SUBCASE("an application may not claim a launch target") {
        CHECK_THROWS_AS(
            Manifest::parse(app_manifest_json(
                {{"launch", {{"applicationId", "com.example.other"}}}})),
            VerificationError);
    }
}

TEST_CASE("launch.mode is declared, never inferred") {
    // §14.4: the alpha's console Hello World "looked like a failed launch"
    // because presentation was inferred from whether a terminal happened to be
    // showing. It is now a declared manifest value.
    CHECK(Manifest::parse(app_manifest_json()).launch_mode == LaunchMode::Gui);
    CHECK(Manifest::parse(app_manifest_json({{"launch", {{"mode", "console"}}}}))
              .launch_mode == LaunchMode::Console);
    CHECK(Manifest::parse(app_manifest_json({{"launch", {{"mode", "service"}}}}))
              .launch_mode == LaunchMode::Service);
    CHECK_THROWS_AS(
        Manifest::parse(app_manifest_json({{"launch", {{"mode", "maybe"}}}})),
        VerificationError);
}

TEST_CASE("a mission-critical manifest may not also permit a compatibility "
          "chain") {
    // §6 FORBID. Rejecting the contradiction in the manifest is better than
    // silently ignoring half of it at launch time.
    CHECK_THROWS_AS(
        Manifest::parse(app_manifest_json(
            {{"execution",
              {{"missionCritical", true},
               {"allowedChains", nlohmann::json::array({"native", "proton"})}}}})),
        VerificationError);
    // The same manifest without the contradiction is fine.
    const Manifest ok = Manifest::parse(app_manifest_json(
        {{"execution",
          {{"missionCritical", true},
           {"allowedChains", nlohmann::json::array({"native"})}}}}));
    CHECK(ok.mission_critical);
    CHECK(ok.effective_allowed_chains() == std::vector<std::string>{"native"});
}

TEST_CASE("execution policy defaults to the boring native path") {
    const Manifest m = Manifest::parse(app_manifest_json());
    CHECK_FALSE(m.mission_critical);
    CHECK(m.effective_allowed_chains() == std::vector<std::string>{"native"});
    CHECK(m.chain_allowed("native"));
    CHECK_FALSE(m.chain_allowed("proton"));
}

// ------------------------------------------------------- strict resolver

TEST_CASE("the strict resolver stops rather than falling back") {
    // §6: "If strict native execution cannot be achieved, execution stops."
    const AppConfig no_overrides;
    SUBCASE("host-ISA-native is available: strict native, no alternatives") {
        const ChainResolution r =
            resolve_chain(native_manifest(true, {"native"}), no_overrides,
                          host_x86(), fake_providers({"fex", "box64", "wine"}));
        REQUIRE(r.ok);
        CHECK(r.strict_resolver);
        CHECK(r.mission_critical);
        CHECK(r.chain.id == "native");
        CHECK(r.chain.native);
        CHECK(r.chain.argv_prefix.empty());
        // Even with every provider installed, NOTHING else may be offered.
        CHECK(r.alternatives.empty());
    }
    SUBCASE("no host-ISA-native realization: execution stops") {
        Manifest m = native_manifest(true, {"native"});
        m.architectures = {"aarch64"}; // not this host
        const ChainResolution r = resolve_chain(
            m, no_overrides, host_x86(), fake_providers({"fex", "box64"}));
        CHECK_FALSE(r.ok);
        CHECK(r.strict_resolver);
        CHECK(r.chain.id.empty());
        CHECK(r.alternatives.empty()); // no "run anyway"
        CHECK(r.reason.find("forbidden") != std::string::npos);
    }
    SUBCASE("a user preference cannot reintroduce a forbidden chain") {
        AppConfig forced;
        forced.compatibility_mode = CompatibilityMode::Manual;
        forced.preferred_chain = {"proton", "fex", "box64"};
        Manifest m = native_manifest(true, {"native"});
        m.architectures = {"aarch64"};
        const ChainResolution r = resolve_chain(
            m, forced, host_x86(), fake_providers({"fex", "box64", "proton"}));
        CHECK_FALSE(r.ok); // still stops
        CHECK(r.chain.id.empty());
    }
}

// ------------------------------------------------------- normal resolver

TEST_CASE("the normal resolver prefers native and explains itself") {
    const ChainResolution r =
        resolve_chain(native_manifest(false, {"native", "box64"}), AppConfig{},
                      host_x86(), fake_providers({"box64"}));
    REQUIRE(r.ok);
    CHECK_FALSE(r.strict_resolver);
    CHECK(r.chain.id == "native");
    // §17: the native happy path must have no compatibility process in it.
    CHECK(r.chain.argv_prefix.empty());
    CHECK(r.reason.find("native") != std::string::npos);
    // box64 is permitted and installed, so it stays offered as an alternative.
    CHECK(has_chain(r.alternatives, "box64"));
}

TEST_CASE("a chain the host lacks is reported, never silently hidden") {
    // §8: "Only chains allowed by the package policy are shown" — but a chain
    // that IS allowed and simply is not installed must say so, so the user can
    // act on it instead of wondering where it went.
    Manifest m = native_manifest(false, {"native", "proton"});
    m.architectures = {"aarch64"}; // no native path here
    const ChainResolution r =
        resolve_chain(m, AppConfig{}, host_x86(), fake_providers({}));
    CHECK_FALSE(r.ok);
    const bool proton_explained =
        std::any_of(r.rejected.begin(), r.rejected.end(),
                    [](const RejectedChain& c) {
                        return c.id == "proton" &&
                               c.reason.find("not installed") !=
                                   std::string::npos;
                    });
    CHECK(proton_explained);
}

TEST_CASE("a user preference narrows and reorders, and can never extend") {
    // §10: "The manifest defines which execution methods are permitted; local
    // configuration records what this machine or user prefers."
    Manifest m = native_manifest(false, {"native", "box64", "fex"});
    m.architectures = {"aarch64"}; // force a compatibility chain

    SUBCASE("a permitted, available preference wins") {
        AppConfig config;
        config.compatibility_mode = CompatibilityMode::Manual;
        config.preferred_chain = {"fex"};
        const ChainResolution r = resolve_chain(
            m, config, host_x86(), fake_providers({"box64", "fex"}));
        REQUIRE(r.ok);
        CHECK(r.chain.id == "fex");
        CHECK(has_chain(r.alternatives, "box64")); // still reachable
    }
    SUBCASE("a preference the package forbids is refused and explained") {
        AppConfig config;
        config.compatibility_mode = CompatibilityMode::Manual;
        config.preferred_chain = {"proton"}; // NOT in allowedChains
        const ChainResolution r = resolve_chain(
            m, config, host_x86(), fake_providers({"box64", "proton"}));
        REQUIRE(r.ok);
        CHECK(r.chain.id != "proton"); // never honoured
        const bool explained = std::any_of(
            r.rejected.begin(), r.rejected.end(), [](const RejectedChain& c) {
                return c.id == "proton" &&
                       c.reason.find("not permitted") != std::string::npos;
            });
        CHECK(explained);
    }
    SUBCASE("automatic mode ignores a stale preference list") {
        AppConfig config;
        config.compatibility_mode = CompatibilityMode::Automatic;
        config.preferred_chain = {"fex"};
        const ChainResolution r = resolve_chain(
            m, config, host_x86(), fake_providers({"box64", "fex"}));
        REQUIRE(r.ok);
        // Automatic follows the PUBLISHER's order, not the stored preference.
        CHECK(r.chain.id == "box64");
    }
}

TEST_CASE("a compatibility chain contributes an argv prefix; native does not") {
    Manifest m = native_manifest(false, {"native", "box64"});
    m.architectures = {"aarch64"};
    const ChainResolution r =
        resolve_chain(m, AppConfig{}, host_x86(), fake_providers({"box64"}));
    REQUIRE(r.ok);
    CHECK(r.chain.id == "box64");
    REQUIRE(r.chain.argv_prefix.size() == 1);
    CHECK(r.chain.argv_prefix[0] == "/usr/bin/box64");
}

// ------------------------------------------------------ per-app overrides

TEST_CASE("per-application overrides live outside the signed package") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const std::string id = "com.example.app";

    // §10: a missing file is exactly "no overrides", never an error.
    const AppConfig fresh = AppConfig::load(paths, id);
    CHECK(fresh.compatibility_mode == CompatibilityMode::Automatic);
    CHECK(fresh.preferred_chain.empty());

    AppConfig config;
    config.id = id;
    config.compatibility_mode = CompatibilityMode::Manual;
    config.preferred_chain = {"proton", "box64"};
    config.save(paths);

    // It is stored under the CONFIG root, not the application store — so
    // changing it cannot touch or invalidate the installed package.
    const fs::path file = AppConfig::file(paths, id);
    REQUIRE(fs::is_regular_file(file));
    CHECK(file.parent_path() == paths.apps_config_dir());
    CHECK(file.string().find(paths.apps_dir().string()) == std::string::npos);

    // And it matches the shape the architecture documents.
    const nlohmann::json doc = nlohmann::json::parse(util::slurp_text(file));
    CHECK(doc["compatibility"]["mode"] == "manual");
    CHECK(doc["compatibility"]["preferredChain"] ==
          nlohmann::json::array({"proton", "box64"}));

    const AppConfig loaded = AppConfig::load(paths, id);
    CHECK(loaded.compatibility_mode == CompatibilityMode::Manual);
    CHECK(loaded.preferred_chain == std::vector<std::string>{"proton", "box64"});

    AppConfig::reset(paths, id);
    CHECK_FALSE(fs::exists(file));
    CHECK(AppConfig::load(paths, id).compatibility_mode ==
          CompatibilityMode::Automatic);
}

TEST_CASE("an application id that is not a safe path component is refused") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    for (const char* bad : {"../escape", "no-dot", "a/b", ""}) {
        CAPTURE(bad);
        CHECK_THROWS_AS(AppConfig::file(paths, bad), Error);
        CHECK_THROWS_AS(ErrorStore(paths).app_dir(bad), Error);
    }
}

// ----------------------------------------------------------- diagnostics

TEST_CASE("an error record is a typed record, not a string") {
    // §9: "Errors are structured records rather than arbitrary strings."
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const ErrorStore store(paths);

    ErrorRecord record;
    record.application_id = "com.example.app";
    record.application_version = "1.0.0";
    record.stage = FailureStage::Runtime;
    record.summary = "the application exited with an error";
    record.detail = "exit code 3 under the native chain";
    record.execution_chain = "native";
    record.launch_mode = "gui";
    record.exit_code = 3;

    const ErrorRecord stored =
        store.record(record, "stdout text\n", "stderr text\n");
    REQUIRE_FALSE(stored.record_path.empty());
    CHECK(fs::is_regular_file(stored.record_path));
    CHECK(fs::is_regular_file(stored.stdout_path));
    CHECK(fs::is_regular_file(stored.stderr_path));

    // It lands in the documented location.
    CHECK(fs::path(stored.record_path).parent_path() ==
          paths.errors_dir() / "com.example.app");

    // Every field §9 names is present and machine-readable.
    const nlohmann::json doc =
        nlohmann::json::parse(util::slurp_text(stored.record_path));
    CHECK(doc["applicationId"] == "com.example.app");
    CHECK(doc["stage"] == "runtime");
    CHECK(doc["executionChain"] == "native");
    CHECK(doc["outcome"]["exitCode"] == 3);
    CHECK(doc["host"]["isa"] == host_architecture());
    CHECK_FALSE(doc["host"]["os"].get<std::string>().empty());
    CHECK_FALSE(doc["runtime"]["version"].get<std::string>().empty());
    CHECK_FALSE(doc["timestamp"].get<std::string>().empty());

    // And it round-trips back into the typed form the frontends use.
    const ErrorRecord parsed =
        ErrorRecord::from_json(util::slurp_text(stored.record_path));
    CHECK(parsed.application_id == "com.example.app");
    CHECK(parsed.stage == FailureStage::Runtime);
    CHECK(parsed.exit_code == 3);
    CHECK(parsed.to_details_text().find("Exit code: 3") != std::string::npos);
}

TEST_CASE("the diagnostic store is bounded in both directions") {
    // §9: "Logs should be size-limited so a broken app cannot generate
    // unlimited diagnostic data."
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const ErrorStore store(paths);
    const std::string id = "com.example.crasher";

    SUBCASE("a huge captured stream is truncated") {
        ErrorRecord record;
        record.application_id = id;
        record.stage = FailureStage::Runtime;
        const std::string huge(ErrorStore::kMaxStreamBytes * 4, 'x');
        const ErrorRecord stored = store.record(record, huge, {});
        REQUIRE_FALSE(stored.stdout_path.empty());
        const std::string kept = util::slurp_text(stored.stdout_path);
        CHECK(kept.size() < huge.size());
        // The truncation is disclosed, not silent.
        CHECK(kept.find("dropped") != std::string::npos);
    }

    SUBCASE("a crash loop cannot grow the store without bound") {
        for (std::size_t i = 0; i < ErrorStore::kMaxRecordsPerApp + 20; ++i) {
            ErrorRecord record;
            record.application_id = id;
            record.stage = FailureStage::Runtime;
            record.summary = "failure " + std::to_string(i);
            (void)store.record(record);
        }
        std::size_t on_disk = 0;
        for (const auto& entry :
             fs::directory_iterator(store.app_dir(id))) {
            if (entry.path().extension() == ".json") ++on_disk;
        }
        CHECK(on_disk <= ErrorStore::kMaxRecordsPerApp);
    }
}

TEST_CASE("error history is newest-first and clearable") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const ErrorStore store(paths);
    const std::string id = "com.example.app";

    CHECK(store.history(id).empty());
    CHECK_FALSE(store.latest(id).has_value());

    for (int i = 0; i < 3; ++i) {
        ErrorRecord record;
        record.application_id = id;
        record.stage = FailureStage::Launch;
        record.summary = "failure " + std::to_string(i);
        (void)store.record(record);
    }
    const std::vector<ErrorRecord> history = store.history(id);
    REQUIRE(history.size() == 3);
    CHECK(history.front().summary == "failure 2"); // newest first
    REQUIRE(store.latest(id).has_value());
    CHECK(store.latest(id)->summary == "failure 2");

    const std::vector<std::string> ids = store.applications_with_errors();
    CHECK(std::find(ids.begin(), ids.end(), id) != ids.end());

    CHECK(store.clear(id) == 3);
    CHECK(store.history(id).empty());
}

TEST_CASE("every failure stage the architecture names round-trips") {
    for (const char* name :
         {"verification", "execution-policy", "chain-resolution",
          "runtime-resolution", "integration", "install", "isolation", "launch",
          "runtime"}) {
        FailureStage stage = FailureStage::Runtime;
        CAPTURE(name);
        REQUIRE(failure_stage_from_string(name, stage));
        CHECK(std::string(to_string(stage)) == name);
    }
    FailureStage ignored = FailureStage::Runtime;
    CHECK_FALSE(failure_stage_from_string("not-a-stage", ignored));
}

// ------------------------------------------------------ launch references

TEST_CASE("a launch reference is a real, verifiable .lexe with no payload") {
    // §15.1: "install and launch artifacts may both use the .lexe format and
    // MIME type, but the internal manifest must distinguish an installable
    // package from a launch reference."
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();

    Manifest app = native_manifest(false, {"native"});
    app.id = "com.example.app";
    app.name = "Example App";
    app.version = "2.1.0";
    app.launch_mode = LaunchMode::Gui;

    const fs::path out = work.dir / "run.lexe";
    write_launch_reference(paths, app, out);
    REQUIRE(fs::is_regular_file(out));

    // It passes the SAME verification pipeline as any other package — a launch
    // reference is not a special case that skips checks.
    const VerificationReport report = verify_package(out, false);
    const std::string failure_detail =
        report.first_failure() != nullptr ? report.first_failure()->detail
                                          : std::string();
    INFO(failure_detail);
    CHECK(report.ok());

    const PackageReader reader(out);
    const Manifest reference = Manifest::parse(reader.read_entry("lexe.json"));
    CHECK(reference.role == PackageRole::Launch);
    CHECK(reference.launch_application_id == "com.example.app");
    CHECK(reference.name == "Example App");
    CHECK(reference.version == "2.1.0");
    CHECK(reference.launch_mode == LaunchMode::Gui);

    // It carries no payload at all: the ELF stays private in the app store.
    for (const PackageEntry& entry : reader.entries()) {
        CHECK(entry.path.rfind("payload/", 0) != 0);
    }

    // Its own id is NOT the application's id: the trust store binds ids to
    // keys, and a locally-signed reference must never bind a real
    // application's id to the machine-local key.
    CHECK(reference.id == std::string(kLaunchReferenceId));
    CHECK(reference.id != app.id);
    CHECK(reference.publisher_public_key == local_launch_key_string(paths));
}

TEST_CASE("the machine-local launch key is stable and owner-only") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();

    const std::string first = local_launch_key_string(paths);
    CHECK_FALSE(first.empty());
    // Stable across calls: regenerating it would invalidate every launch
    // reference already on the user's desktop.
    CHECK(local_launch_key_string(paths) == first);

    const fs::path keyfile = paths.keys_dir() / "local-root.json";
    REQUIRE(fs::is_regular_file(keyfile));
#ifndef _WIN32
    const fs::perms perms = fs::status(keyfile).permissions();
    CHECK((perms & fs::perms::group_all) == fs::perms::none);
    CHECK((perms & fs::perms::others_all) == fs::perms::none);
#endif
}

TEST_CASE("a launch reference cannot be generated for another reference") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    Manifest reference;
    reference.role = PackageRole::Launch;
    reference.id = kLaunchReferenceId;
    reference.launch_application_id = "com.example.app";
    CHECK_THROWS_AS(
        write_launch_reference(paths, reference, work.dir / "nested.lexe"),
        Error);
}

TEST_CASE("the canonical launch reference path is per application") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path p = launch_reference_path(paths, "com.example.app");
    CHECK(p.parent_path() == paths.launch_dir());
    CHECK(p.filename() == "com.example.app.lexe");
    CHECK_THROWS_AS(launch_reference_path(paths, "../escape"), Error);
}

// -------------------------------------------------------------- providers

TEST_CASE("provider probing is truthful and side-effect free") {
    const ProviderSet set = probe_providers();
    // Every provider the runtime knows about is REPORTED, present or not, so
    // a frontend can show "not installed" rather than silently omitting it.
    for (const char* id : {"fex", "box64", "wine", "proton", "qemu-user"}) {
        CAPTURE(id);
        const Provider* provider = set.find(id);
        REQUIRE(provider != nullptr);
        CHECK_FALSE(provider->detail.empty());
        // A provider is only "available" when an executable was actually found.
        CHECK(provider->available == !provider->executable.empty());
    }
    CHECK(set.find("not-a-provider") == nullptr);
}

TEST_CASE("known chain ids include the layered combinations the architecture "
          "names") {
    const std::vector<std::string> ids = known_chain_ids();
    for (const char* expected :
         {"native", "fex", "box64", "wine", "proton", "proton+fex",
          "proton+box64"}) {
        CAPTURE(expected);
        CHECK(std::find(ids.begin(), ids.end(), expected) != ids.end());
    }
}

TEST_CASE("a layered chain applies the ISA layer innermost") {
    // §8: "Windows x86-64 on ARM64 Linux -> Wine / Proton + ISA translation".
    const ProviderSet providers = fake_providers({"proton", "fex"});
    const std::optional<ExecutionChain> chain =
        make_chain("proton+fex", providers);
    REQUIRE(chain.has_value());
    CHECK(chain->layers == std::vector<std::string>{"proton", "fex"});
    REQUIRE(chain->argv_prefix.size() == 2);
    CHECK(chain->argv_prefix[0] == "/usr/bin/fex");    // translates first
    CHECK(chain->argv_prefix[1] == "/usr/bin/proton"); // then the OS layer
    // A nonsensical ordering is not a chain.
    CHECK_FALSE(make_chain("fex+proton", providers).has_value());
}


// ---------------------------------------------------------------------------
// A foreign-OS payload resolves to a foreign-OS chain — and to nothing else.
//
// The chain machinery was real before any package could declare a Windows
// payload; these cases connect the two halves, so the Wine/Proton paths are
// reachable from a manifest instead of only from a unit test that builds a
// resolution by hand.
// ---------------------------------------------------------------------------

Manifest windows_manifest(const std::vector<std::string>& chains = {"wine",
                                                                    "proton"}) {
    Manifest m;
    m.lexe_version = "0.1";
    m.id = "com.example.windows";
    m.name = "Windows App";
    m.version = "1.0.0";
    m.publisher_name = "P";
    m.publisher_public_key =
        "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    m.application_type = "windows";
    m.application_kind = ApplicationType::Windows;
    m.architectures = {"x86_64"};
    m.entrypoint_executable = "bin/app.exe";
    m.install_mode = "bundled";
    m.allowed_chains = chains;
    return m;
}

TEST_CASE("a windows payload never resolves to the native chain") {
    // The host is x86_64 and the package declares x86_64 — so the ISAs match
    // exactly, and native would be chosen for any Linux payload. It is not
    // chosen here, because matching ISAs do not make a PE a Linux program.
    const ChainResolution resolution = resolve_chain(
        windows_manifest(), AppConfig{}, host_x86(), fake_providers({"wine"}));
    REQUIRE(resolution.ok);
    CHECK(resolution.chain.id == "wine");
    CHECK_FALSE(resolution.chain.native);
    CHECK_FALSE(resolution.chain.argv_prefix.empty());
    CHECK_FALSE(has_chain(resolution.alternatives, "native"));
}

TEST_CASE("a windows payload with no foreign-OS layer on the host stops") {
    // Wine and Proton are permitted by the package and absent from the host.
    const ChainResolution resolution =
        resolve_chain(windows_manifest(), AppConfig{}, host_x86(),
                      fake_providers({"fex", "box64"}));
    CHECK_FALSE(resolution.ok);
    // Everything permitted but unavailable is reported WITH A REASON, never
    // silently hidden — that is how a user finds out what to install.
    CHECK_FALSE(resolution.rejected.empty());
    bool wine_explained = false;
    for (const RejectedChain& rejected : resolution.rejected) {
        if (rejected.id == "wine") {
            wine_explained = !rejected.reason.empty();
        }
    }
    CHECK(wine_explained);
}

TEST_CASE("the strict resolver refuses a windows payload outright") {
    Manifest m = windows_manifest();
    m.mission_critical = true; // the parser rejects this; the resolver must too
    const ChainResolution resolution = resolve_chain(
        m, AppConfig{}, host_x86(), fake_providers({"wine", "proton"}));
    CHECK(resolution.strict_resolver);
    CHECK_FALSE(resolution.ok);
    CHECK(resolution.reason.find("Linux-native") != std::string::npos);
    CHECK(resolution.chain.id.empty());
}

TEST_CASE("a user preference still cannot extend what the publisher permitted") {
    AppConfig config;
    config.compatibility_mode = CompatibilityMode::Manual;
    config.preferred_chain = {"proton"}; // not in the package list
    const ChainResolution resolution =
        resolve_chain(windows_manifest({"wine"}), AppConfig{}, host_x86(),
                      fake_providers({"wine", "proton"}));
    REQUIRE(resolution.ok);
    CHECK(resolution.chain.id == "wine");

    const ChainResolution narrowed =
        resolve_chain(windows_manifest({"wine"}), config, host_x86(),
                      fake_providers({"wine", "proton"}));
    // The preference names a chain the signed policy does not permit, so it
    // cannot take effect — the publisher's list is a ceiling, not a hint.
    CHECK_FALSE(narrowed.chain.id == "proton");
}

TEST_CASE("a Windows-on-ARM host layers ISA translation under the OS layer") {
    // §8's worked example: a Windows x86-64 payload on ARM64 Linux.
    HostFacts arm;
    arm.isa = "aarch64";
    arm.os = "linux";
    const ChainResolution resolution =
        resolve_chain(windows_manifest({"proton+fex", "wine"}), AppConfig{},
                      arm, fake_providers({"proton", "fex"}));
    REQUIRE(resolution.ok);
    CHECK(resolution.chain.id == "proton+fex");
    REQUIRE(resolution.chain.argv_prefix.size() == 2);
    CHECK(resolution.chain.argv_prefix[0] == "/usr/bin/fex");
    CHECK(resolution.chain.argv_prefix[1] == "/usr/bin/proton");
}

} // TEST_SUITE

TEST_SUITE("integration-durability") {

/// A package that also carries icons, so integration has something to register.
fs::path make_package_with_icons(const fs::path& work,
                                 const crypto::KeyPair& key,
                                 const std::string& id) {
    test::TestAppSpec spec;
    spec.id = id;
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree =
        test::make_test_app_tree(work / ("tree-" + id), spec);

    const fs::path icons = work / ("icons-" + id);
    util::spit(icons / "64.png", std::string_view("png-64-bytes"));
    util::spit(icons / "128.png", std::string_view("png-128-bytes"));
    util::spit(icons / "256.png", std::string_view("png-256-bytes"));
    util::spit(icons / "scalable.svg", std::string_view("<svg/>"));

    PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    inputs.icons_dir = icons;
    const fs::path out = work / (id + ".lexe");
    PackageWriter::write(inputs, key, out);
    return out;
}

std::size_t registered_icons(const Paths& paths, const std::string& id) {
    std::size_t n = 0;
    for (const IntegrationArtifact& a : IntegrationState::load(paths).scope(id)) {
        if (a.kind == ArtifactKind::AppIcon) ++n;
    }
    return n;
}

TEST_CASE("repair restores a lost icon instead of de-registering the rest") {
    // REGRESSION. repair() used to look for icons in the VERSION directory,
    // where they never were: install extracted them to a scratch dir and
    // deleted it. install_app() therefore recorded zero icon artifacts, and
    // because it replaces the application's whole scope, repairing an app with
    // one missing icon silently DE-REGISTERED the other three — leaving them
    // orphaned on disk, unrepairable, and not removed by uninstall.
    //
    // The architectural requirement this violated: per-application desktop
    // artifacts must be regenerable FROM INSTALLED STATE, with no package
    // file present. Icons are now retained in the per-version meta store.
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const std::string id = "com.example.icons";

    const fs::path pkg = make_package_with_icons(work.dir, key, id);
    Installer installer(paths);
    InstallOptions options;
    options.desktop_integration = true;
    installer.install(pkg, options);

    // All four icons are installed AND recorded.
    CHECK(registered_icons(paths, id) == 4);
    const fs::path icon64 =
        paths.icons_dir() / "64x64" / "apps" / ("lexe-" + id + ".png");
    REQUIRE(fs::is_regular_file(icon64));

    // The icon SOURCE survives the install — this is what makes repair
    // possible without the original package.
    const Registry registry(paths);
    const fs::path retained =
        registry.meta_dir(id, registry.current_version(id)) / "icons";
    CHECK(fs::is_regular_file(retained / "64.png"));
    CHECK(fs::is_regular_file(retained / "scalable.svg"));

    // Lose one icon the way a theme cleanup or a bad uninstall would.
    fs::remove(icon64);
    DesktopIntegration integration(paths);
    const IntegrationReport broken = integration.verify();
    CHECK_FALSE(broken.ok);

    const IntegrationReport repaired = integration.repair();
    CHECK(repaired.ok);
    // The lost icon is BACK...
    CHECK(fs::is_regular_file(icon64));
    // ...with the right bytes, not an empty placeholder.
    CHECK(util::slurp_text(icon64) == "png-64-bytes");
    // ...and nothing was quietly de-registered.
    CHECK(registered_icons(paths, id) == 4);
    CHECK(integration.verify().ok);
}

TEST_CASE("integration never forgets an artifact it cannot regenerate") {
    // The legacy case: an application installed by a runtime that did not
    // retain icons. install_app() has no source, but the registrations that
    // DO exist must be carried forward — dropping them would make their later
    // loss undetectable and leave the files behind on uninstall.
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const std::string id = "com.example.legacy";

    const fs::path pkg = make_package_with_icons(work.dir, key, id);
    Installer installer(paths);
    InstallOptions options;
    options.desktop_integration = true;
    installer.install(pkg, options);
    REQUIRE(registered_icons(paths, id) == 4);

    // Simulate the older layout: the retained icon source is gone, but the
    // installed icon files are still there.
    const Registry registry(paths);
    util::remove_recursive(
        registry.meta_dir(id, registry.current_version(id)) / "icons");

    DesktopIntegration integration(paths);
    const IntegrationReport report = integration.repair();
    CHECK(report.ok);
    // Still registered, still verifiable — not silently forgotten.
    CHECK(registered_icons(paths, id) == 4);
    CHECK(integration.verify().ok);

    // And uninstall still removes them, because they were never forgotten.
    installer.uninstall(id, Installer::UninstallMode::AppOnly);
    CHECK_FALSE(fs::exists(paths.icons_dir() / "64x64" / "apps" /
                           ("lexe-" + id + ".png")));
    CHECK(registered_icons(paths, id) == 0);
}

TEST_CASE("a launch reference is created at install and repaired when lost") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const std::string id = "com.example.launchref";

    const fs::path pkg = make_package_with_icons(work.dir, key, id);
    Installer installer(paths);
    InstallOptions options;
    options.desktop_integration = true;
    installer.install(pkg, options);

    const fs::path run_lexe = launch_reference_path(paths, id);
    REQUIRE(fs::is_regular_file(run_lexe));
    CHECK(verify_package(run_lexe, false).ok());

    // Lose it the way a cleaned-up home directory would.
    fs::remove(run_lexe);
    DesktopIntegration integration(paths);
    CHECK_FALSE(integration.verify().ok);
    CHECK(integration.repair().ok);
    REQUIRE(fs::is_regular_file(run_lexe));

    // The regenerated reference is a real, verifiable launch artifact for the
    // right application — regenerated from installed state, no package needed.
    CHECK(verify_package(run_lexe, false).ok());
    const PackageReader reader(run_lexe);
    const Manifest reference = Manifest::parse(reader.read_entry("lexe.json"));
    CHECK(reference.role == PackageRole::Launch);
    CHECK(reference.launch_application_id == id);
}

} // TEST_SUITE

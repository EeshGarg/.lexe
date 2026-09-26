// Proton chain tests — regression coverage for three defects that made the
// Proton path look implemented while it could never have run anything.
//
// All three were invisible to the existing suite because every test built a
// chain from a SYNTHESIZED ProviderSet with an executable path the test chose.
// That exercises the resolver and skips the two things that were wrong: how
// Proton is FOUND, and how it is INVOKED once found.
//
//   1. discovery was `util::find_on_path("proton")`. Proton is not a
//      distribution package and is never on $PATH, so on a machine with Proton
//      installed the probe answered "not installed on this host": every Proton
//      chain resolved as unavailable, and the failure read as policy rather
//      than as a bug.
//
//   2. the chain's argv prefix was just the Proton path. Proton's entry point
//      is a Python dispatcher that takes a VERB; `proton <exe>` runs nothing.
//
//   3. nothing supplied STEAM_COMPAT_DATA_PATH or
//      STEAM_COMPAT_CLIENT_INSTALL_PATH. Proton exits 1 without either — "No
//      compat data path?" for the first, a Python KeyError for the second —
//      and it does not create the compat directory itself.
//
// These are unit tests, so they check the DECISIONS. That a real Windows PE
// actually executes through a real Proton is tests/acceptance/07_proton.sh,
// which is the only thing that can settle it.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/util.hpp"
#include "lexe/runtime/execpolicy.hpp"
#include "lexe/sandbox/isolation.hpp"

#include <algorithm>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

/// Set an environment variable for the duration of a scope and put back exactly
/// what was there — including "it was not set at all", which matters here
/// because HOME and LEXE_PROTON both change the answer discovery gives.
/// Modelled on the guard in tests/test_paths.cpp.
class EnvGuard {
  public:
    EnvGuard(std::string name, std::optional<std::string> value)
        : name_(std::move(name)), previous_(util::get_env(name_)) {
        if (value.has_value()) {
            util::set_env(name_, *value);
        } else {
            util::unset_env(name_);
        }
    }
    ~EnvGuard() {
        if (previous_.has_value()) {
            util::set_env(name_, *previous_);
        } else {
            util::unset_env(name_);
        }
    }
    EnvGuard(const EnvGuard&) = delete;
    EnvGuard& operator=(const EnvGuard&) = delete;

  private:
    std::string name_;
    std::optional<std::string> previous_;
};

bool any_contains(const std::vector<std::string>& haystack,
                  const std::string& fragment) {
    return std::any_of(haystack.begin(), haystack.end(),
                       [&](const std::string& s) {
                           return s.find(fragment) != std::string::npos;
                       });
}

/// A ProviderSet with Proton present at `path` and nothing else — so a chain
/// built from it is unambiguous.
ProviderSet only_proton(const std::string& path) {
    ProviderSet set;
    Provider proton;
    proton.id = "proton";
    proton.name = "Proton";
    proton.kind = ChainLayerKind::ForeignOs;
    proton.available = true;
    proton.executable = path;
    proton.origin = "test";
    set.providers.push_back(std::move(proton));
    return set;
}

} // namespace

TEST_SUITE("proton") {

// ------------------------------------------------------------------ discovery

TEST_CASE("Proton is looked for where Proton actually lives, not on $PATH") {
    const std::vector<std::string> searched = provider_search_paths("proton");
    REQUIRE_FALSE(searched.empty());

    // Every candidate must be an absolute path ending in the proton script.
    for (const std::string& candidate : searched) {
        CAPTURE(candidate);
        CHECK(candidate.front() == '/');
        CHECK(candidate.size() > 7);
        CHECK(candidate.rfind("/proton") == candidate.size() - 7);
    }
}

TEST_CASE("the Steam layouts a real machine uses are all searched") {
    // Asserted as behaviour rather than as a literal list: with HOME pointed at
    // a scratch tree containing each layout, discovery must reach into each one.
    // A regression that dropped a location would show up here as a directory
    // whose contents never appear among the candidates.
    const fs::path home = test::unique_temp_dir("lexe-proton-home-");
    const EnvGuard scoped_home("HOME", home.string());
    const EnvGuard no_override("LEXE_PROTON", std::nullopt);

    const std::vector<std::string> layouts = {
        ".steam/root/compatibilitytools.d",
        ".steam/steam/compatibilitytools.d",
        ".local/share/Steam/compatibilitytools.d",
        ".steam/steam/steamapps/common",
        ".local/share/Steam/steamapps/common",
    };
    for (std::size_t i = 0; i < layouts.size(); ++i) {
        // A distinctively named build inside each, so a candidate can be traced
        // back to the layout it came from.
        fs::create_directories(home / layouts[i] /
                               ("Marker-" + std::to_string(i)));
    }

    const std::vector<std::string> searched = provider_search_paths("proton");
    for (const std::string& layout : layouts) {
        CAPTURE(layout);
        INFO("this Steam layout is not searched, so Proton installed there is "
             "invisible to the runtime");
        CHECK(any_contains(searched, layout));
    }
    fs::remove_all(home);
}

TEST_CASE("a build that exists is found, and the choice is reproducible") {
    const fs::path home = test::unique_temp_dir("lexe-proton-home-");
    const EnvGuard scoped_home("HOME", home.string());
    const EnvGuard no_override("LEXE_PROTON", std::nullopt);

    const fs::path tools = home / ".steam/root/compatibilitytools.d";
    // Deliberately created in an order that is NOT the sorted order, so a probe
    // that depended on readdir order would give a different answer per run.
    for (const char* name : {"Zzz-Proton", "Aaa-Proton", "Mmm-Proton"}) {
        fs::create_directories(tools / name);
        util::spit(tools / name / "proton", "#!/usr/bin/env python3\n");
    }

    const std::vector<std::string> first = provider_search_paths("proton");
    const std::vector<std::string> second = provider_search_paths("proton");
    CHECK(first == second); // reproducible, not readdir-dependent

    // Sorted within a directory, so "which one wins" is a rule and not luck.
    REQUIRE(first.size() >= 3);
    CHECK(first[0].find("Aaa-Proton") != std::string::npos);
    CHECK(first[1].find("Mmm-Proton") != std::string::npos);
    CHECK(first[2].find("Zzz-Proton") != std::string::npos);

    const ProviderSet probed = probe_providers();
    const Provider* proton = probed.find("proton");
    REQUIRE(proton != nullptr);
    CHECK(proton->available);
    CHECK(proton->executable == first[0]);
    CHECK(proton->origin == "Steam compatibility tool");

    fs::remove_all(home);
}

TEST_CASE("LEXE_PROTON names a specific build and wins over the search") {
    const fs::path home = test::unique_temp_dir("lexe-proton-home-");
    const EnvGuard scoped_home("HOME", home.string());

    const fs::path tools = home / ".steam/root/compatibilitytools.d";
    fs::create_directories(tools / "Aaa-Proton");
    util::spit(tools / "Aaa-Proton" / "proton", "#!/usr/bin/env python3\n");

    const fs::path chosen = home / "elsewhere" / "Chosen-Proton";
    fs::create_directories(chosen);
    util::spit(chosen / "proton", "#!/usr/bin/env python3\n");

    const EnvGuard override_env("LEXE_PROTON", (chosen / "proton").string());
    const std::vector<std::string> searched = provider_search_paths("proton");
    REQUIRE_FALSE(searched.empty());
    CHECK(searched[0] == (chosen / "proton").string());

    const ProviderSet probed = probe_providers();
    const Provider* proton = probed.find("proton");
    REQUIRE(proton != nullptr);
    CHECK(proton->executable == (chosen / "proton").string());
    CHECK(proton->origin == "LEXE_PROTON override");

    fs::remove_all(home);
}

TEST_CASE("when nothing is installed the reason says where it looked") {
    const fs::path home = test::unique_temp_dir("lexe-proton-home-");
    const EnvGuard scoped_home("HOME", home.string());
    const EnvGuard no_override("LEXE_PROTON", std::nullopt);

    const ProviderSet probed = probe_providers();
    const Provider* proton = probed.find("proton");
    REQUIRE(proton != nullptr);
    CHECK_FALSE(proton->available);
    // "not installed on this host" alone is the same sentence whether the
    // runtime searched the right places and found nothing or searched the wrong
    // place, which is what made a discovery bug read as policy. The detail has
    // to say that it looked, and where to see where.
    CHECK(proton->detail.find("searched") != std::string::npos);
    CHECK(proton->detail.find("lexe runtime show proton") != std::string::npos);

    // And the locations themselves are answerable without a Proton installed.
    const std::vector<std::string> roots = provider_search_roots("proton");
    CHECK_FALSE(roots.empty());
    CHECK(any_contains(roots, "compatibilitytools.d"));
    CHECK(any_contains(roots, "steamapps/common"));
    // A provider that genuinely lives on $PATH has no roots to report.
    CHECK(provider_search_roots("wine").empty());

    fs::remove_all(home);
}

// ------------------------------------------------------------------ invocation

TEST_CASE("the Proton chain invokes Proton with a verb") {
    const ProviderSet providers = only_proton("/opt/proton/proton");
    const std::optional<ExecutionChain> chain = make_chain("proton", providers);
    REQUIRE(chain.has_value());

    REQUIRE(chain->argv_prefix.size() >= 2);
    CHECK(chain->argv_prefix[0] == "/opt/proton/proton");
    // `proton <exe>` is not a command Proton has; without a verb it runs
    // nothing at all and the chain can never have worked.
    CHECK(chain->argv_prefix[1] == "runinprefix");
}

TEST_CASE("Wine takes no verb — the fix did not spread to the wrong provider") {
    ProviderSet providers;
    Provider wine;
    wine.id = "wine";
    wine.name = "Wine";
    wine.kind = ChainLayerKind::ForeignOs;
    wine.available = true;
    wine.executable = "/usr/bin/wine";
    providers.providers.push_back(std::move(wine));

    const std::optional<ExecutionChain> chain = make_chain("wine", providers);
    REQUIRE(chain.has_value());
    REQUIRE(chain->argv_prefix.size() == 1);
    CHECK(chain->argv_prefix[0] == "/usr/bin/wine");
    CHECK(chain->env.empty());
    CHECK(chain->required_data_dirs.empty());
}

// ------------------------------------------------------------------ environment

TEST_CASE("the Proton chain declares the environment Proton refuses to start without") {
    const ProviderSet providers = only_proton("/opt/proton/proton");
    const std::optional<ExecutionChain> chain = make_chain("proton", providers);
    REQUIRE(chain.has_value());

    // Missing STEAM_COMPAT_DATA_PATH: "Proton: No compat data path?", exit 1.
    // Missing STEAM_COMPAT_CLIENT_INSTALL_PATH: a Python KeyError, exit 1.
    REQUIRE(chain->env.count("STEAM_COMPAT_DATA_PATH") == 1);
    REQUIRE(chain->env.count("STEAM_COMPAT_CLIENT_INSTALL_PATH") == 1);

    // Both must be SANDBOX paths under the application's own data root. A host
    // path here would put Proton's prefix in the user's home and expose their
    // real Steam installation to the application.
    const std::string data = chain->env.at("STEAM_COMPAT_DATA_PATH");
    const std::string client = chain->env.at("STEAM_COMPAT_CLIENT_INSTALL_PATH");
    CHECK(data.rfind(kSandboxData, 0) == 0);
    CHECK(client.rfind(kSandboxData, 0) == 0);
    CHECK(data == kSandboxProtonPrefix);
    CHECK(client == kSandboxProtonSteam);
}

TEST_CASE("the Proton chain asks for the compat directory to exist") {
    // Proton does not create STEAM_COMPAT_DATA_PATH. With it absent, wine fails
    // with "chdir to <path>/pfx : No such file or directory" and exits 1.
    const ProviderSet providers = only_proton("/opt/proton/proton");
    const std::optional<ExecutionChain> chain = make_chain("proton", providers);
    REQUIRE(chain.has_value());
    REQUIRE(chain->required_data_dirs.size() == 1);
    CHECK(chain->required_data_dirs[0] == ".proton");

    // It must be relative and must not climb out of the data root: the launcher
    // creates these, so an absolute or ../ entry would establish a directory
    // outside the application's own state.
    for (const std::string& relative : chain->required_data_dirs) {
        CAPTURE(relative);
        CHECK(relative.front() != '/');
        CHECK(relative.find("..") == std::string::npos);
    }
}

TEST_CASE("a chain's environment reaches the sandbox, and only by declaration") {
    IsolationRequest req;
    req.app_id = "com.example.windows";
    req.app_root = "/apps/com.example.windows/1.0.0";
    req.entrypoint = "/apps/com.example.windows/1.0.0/bin/app.exe";
    req.data_root = "/data/com.example.windows";
    req.cache_root = "/cache/com.example.windows";
    // Something the caller had that must NOT survive, alongside the chain's own.
    req.inherited_env = {{"STEAM_COMPAT_DATA_PATH", "/home/someone/real/steam"},
                         {"LD_PRELOAD", "/evil.so"}};
    req.chain_env = {{"STEAM_COMPAT_DATA_PATH", kSandboxProtonPrefix},
                     {"STEAM_COMPAT_CLIENT_INSTALL_PATH", kSandboxProtonSteam}};

    const std::map<std::string, std::string> env = sanitize_environment(req);

    // The chain's value, not the caller's: inheriting it would hand the
    // application the user's real Steam paths.
    REQUIRE(env.count("STEAM_COMPAT_DATA_PATH") == 1);
    CHECK(env.at("STEAM_COMPAT_DATA_PATH") == kSandboxProtonPrefix);
    CHECK(env.at("STEAM_COMPAT_CLIENT_INSTALL_PATH") == kSandboxProtonSteam);
    // And the allowlist still holds for everything else.
    CHECK(env.count("LD_PRELOAD") == 0);
}

TEST_CASE("a native launch gets no Proton environment at all") {
    IsolationRequest req;
    req.app_id = "com.example.native";
    req.app_root = "/apps/com.example.native/1.0.0";
    req.entrypoint = "/apps/com.example.native/1.0.0/bin/app";
    req.data_root = "/data/com.example.native";
    req.cache_root = "/cache/com.example.native";
    // chain_env left empty: the native chain contributes nothing.

    const std::map<std::string, std::string> env = sanitize_environment(req);
    CHECK(env.count("STEAM_COMPAT_DATA_PATH") == 0);
    CHECK(env.count("STEAM_COMPAT_CLIENT_INSTALL_PATH") == 0);
}

// ------------------------------------------------------------------ the sandbox

TEST_CASE("a Proton tree outside /usr is bound into the sandbox") {
    // A compatibility layer that is not reachable inside the sandbox cannot run
    // the application, and a Steam Proton tree is never under /usr.
    IsolationRequest req;
    req.app_id = "com.example.windows";
    req.app_root = "/apps/com.example.windows/1.0.0";
    req.entrypoint = "/apps/com.example.windows/1.0.0/bin/app.exe";
    req.data_root = "/data/com.example.windows";
    req.cache_root = "/cache/com.example.windows";
    req.compatibility_paths = {
        "/home/someone/.steam/root/compatibilitytools.d/GE-Proton/proton",
        "runinprefix"}; // the verb is not a path and must be ignored

    IsolationCapabilities caps;
    caps.status = CapabilityStatus::Available;
    caps.backend_present = caps.user_namespaces = true;
    caps.network_namespaces = caps.bind_mounts = true;

    const IsolationPlan plan = build_plan(req, caps);

    bool bound = false;
    for (const BindMount& bind : plan.binds) {
        if (bind.host.find("GE-Proton") == std::string::npos) continue;
        bound = true;
        // Read-only: a compatibility layer gets no more authority than the
        // application it runs.
        CHECK(bind.read_only);
    }
    INFO("the Proton installation prefix must be bound, or the chain cannot run");
    CHECK(bound);

    // The verb must not have been treated as a path to bind.
    for (const BindMount& bind : plan.binds) {
        CAPTURE(bind.host);
        CHECK(bind.host != "runinprefix");
    }
}

} // TEST_SUITE

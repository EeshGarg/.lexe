// isolation engine tests (runtime-trust WS7): the PURE policy/env/render
// functions and the fake backend. These run on every platform (they execute
// nothing). Real bubblewrap enforcement is proven in the Linux integration
// tests (test_isolation_linux.cpp).

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/isolation.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

using namespace lexe;

namespace {

IsolationCapabilities full_caps() {
    IsolationCapabilities c;
    c.status = CapabilityStatus::Available;
    c.backend_present = true;
    c.user_namespaces = true;
    c.network_namespaces = true;
    c.bind_mounts = true;
    return c;
}

IsolationRequest sample_request(bool network) {
    IsolationRequest r;
    r.app_id = "com.example.app";
    r.app_root = "/lexehome/apps/com.example.app/versions/1.0.0";
    r.entrypoint = r.app_root / "bin/app";
    r.data_root = "/lexehome/data/com.example.app";
    r.cache_root = "/lexehome/cache/apps/com.example.app";
    r.network_allowed = network;
    r.args = {"--flag", "a b", "semi;colon", "$SUBST", "back`tick`"};
    r.inherited_env = {{"LD_PRELOAD", "/evil.so"},
                       {"PATH", "/attacker/bin"},
                       {"SECRET_TOKEN", "hunter2"}};
    return r;
}

bool argv_has_pair(const std::vector<std::string>& a, const std::string& x,
                   const std::string& y) {
    for (std::size_t i = 0; i + 1 < a.size(); ++i) {
        if (a[i] == x && a[i + 1] == y) return true;
    }
    return false;
}

bool argv_has(const std::vector<std::string>& a, const std::string& x) {
    return std::find(a.begin(), a.end(), x) != a.end();
}

} // namespace

TEST_SUITE("isolation") {

TEST_CASE("environment is reduced to a safe allowlist (dangerous vars dropped)") {
    const auto env = sanitize_environment(sample_request(false));
    // Only the allowlist keys are present.
    CHECK(env.at("HOME") == kSandboxData);
    CHECK(env.at("PATH") == "/usr/bin:/bin"); // NOT the attacker's PATH
    CHECK(env.at("TMPDIR") == kSandboxTemp);
    CHECK(env.at("LEXE_APP_ID") == "com.example.app");
    CHECK(env.at("LEXE_APP_DATA") == kSandboxData);
    // Injection / secret variables are gone.
    CHECK(env.count("LD_PRELOAD") == 0);
    CHECK(env.count("LD_LIBRARY_PATH") == 0);
    CHECK(env.count("PYTHONPATH") == 0);
    CHECK(env.count("SECRET_TOKEN") == 0);
    CHECK(env.count("DBUS_SESSION_BUS_ADDRESS") == 0);
}

TEST_CASE("plan maps controls to Enforced and picks network by permission") {
    const IsolationPlan denied = build_plan(sample_request(false), full_caps());
    CHECK(denied.network_shared == false);
    CHECK(denied.controls.at(IsolationControl::NetworkDenied) ==
          ControlState::Enforced);
    CHECK(denied.controls.at(IsolationControl::AppRootReadOnly) ==
          ControlState::Enforced);
    CHECK(denied.controls.at(IsolationControl::PrivateData) ==
          ControlState::Enforced);
    CHECK(denied.controls.at(IsolationControl::HomeHidden) ==
          ControlState::Enforced);
    CHECK(denied.controls.at(IsolationControl::EnvironmentSanitized) ==
          ControlState::Enforced);

    const IsolationPlan allowed = build_plan(sample_request(true), full_caps());
    CHECK(allowed.network_shared == true);
    CHECK(allowed.controls.at(IsolationControl::NetworkDenied) ==
          ControlState::NotApplicable);
}

TEST_CASE("plan binds the app root read-only and the private roots writable") {
    const IsolationPlan p = build_plan(sample_request(false), full_caps());
    bool approot_ro = false, data_rw = false, cache_rw = false;
    for (const BindMount& b : p.binds) {
        if (b.host == "/lexehome/apps/com.example.app/versions/1.0.0") {
            approot_ro = b.read_only && b.sandbox == b.host;
        }
        if (b.host == "/lexehome/data/com.example.app") {
            data_rw = !b.read_only && b.sandbox == kSandboxData;
        }
        if (b.host == "/lexehome/cache/apps/com.example.app") {
            cache_rw = !b.read_only && b.sandbox == kSandboxCache;
        }
    }
    CHECK(approot_ro);
    CHECK(data_rw);
    CHECK(cache_rw);
    CHECK(std::find(p.tmpfs.begin(), p.tmpfs.end(), kSandboxTemp) !=
          p.tmpfs.end());
    // No unrelated application's data root is mounted.
    for (const BindMount& b : p.binds) {
        CHECK(b.host.find("other.app") == std::string::npos);
    }
    // Working directory is not the caller's cwd.
    CHECK(p.working_dir == kSandboxData);
}

TEST_CASE("FAIL CLOSED: network denial required but namespaces unavailable") {
    IsolationCapabilities caps = full_caps();
    caps.network_namespaces = false;
    caps.status = CapabilityStatus::PartiallyAvailable;
    // network absent + no netns -> cannot deny -> refuse (no unconfined launch).
    CHECK_THROWS_AS(build_plan(sample_request(false), caps), lexe::IsolationError);
    // But if network IS permitted, no netns is needed, so it proceeds.
    CHECK_NOTHROW(build_plan(sample_request(true), caps));
}

TEST_CASE("FAIL CLOSED: no user namespaces / bind mounts -> no plan") {
    IsolationCapabilities caps;
    caps.status = CapabilityStatus::Unavailable;
    caps.user_namespaces = false;
    caps.bind_mounts = false;
    CHECK_THROWS_AS(build_plan(sample_request(false), caps), lexe::IsolationError);
    CHECK_THROWS_AS(build_plan(sample_request(true), caps), lexe::IsolationError);
}

TEST_CASE("bwrap argv is deterministic and passes args verbatim (no shell)") {
    const IsolationPlan p = build_plan(sample_request(false), full_caps());
    const std::vector<std::string> a = render_bwrap_argv(p, "/usr/bin/bwrap");

    CHECK(a.front() == "/usr/bin/bwrap");
    CHECK(argv_has(a, "--unshare-user"));
    CHECK(argv_has(a, "--unshare-pid"));
    CHECK(argv_has(a, "--unshare-net"));   // network denied
    CHECK(argv_has(a, "--clearenv"));
    CHECK(argv_has(a, "--die-with-parent"));
    CHECK(argv_has_pair(a, "--ro-bind", "/usr"));
    CHECK(argv_has_pair(a, "--chdir", kSandboxData));

    // Everything after "--" is the app argv, exactly, as separate elements —
    // shell metacharacters are inert because there is no shell.
    const auto dashdash = std::find(a.begin(), a.end(), "--");
    REQUIRE(dashdash != a.end());
    const std::vector<std::string> app(dashdash + 1, a.end());
    CHECK(app == std::vector<std::string>{
                     "/lexehome/apps/com.example.app/versions/1.0.0/bin/app",
                     "--flag", "a b", "semi;colon", "$SUBST", "back`tick`"});

    // Determinism: same inputs -> identical argv.
    CHECK(render_bwrap_argv(p, "/usr/bin/bwrap") == a);

    // network-allowed plan shares the net namespace (no --unshare-net).
    const IsolationPlan pn = build_plan(sample_request(true), full_caps());
    CHECK_FALSE(argv_has(render_bwrap_argv(pn, "/usr/bin/bwrap"), "--unshare-net"));
}

TEST_CASE("the fake backend records the plan and never executes on setup fail") {
    FakeIsolationBackend backend(full_caps());
    backend.exit_code = 3;
    const IsolationPlan p = build_plan(sample_request(false), full_caps());

    const IsolationResult r = backend.run(p);
    CHECK(backend.ran);
    CHECK(r.exit_code == 3);
    CHECK(backend.last_plan.app_argv == p.app_argv);
    CHECK(r.enforced.at(IsolationControl::NetworkDenied) == ControlState::Enforced);

    FakeIsolationBackend broken(full_caps());
    broken.fail_setup = true;
    CHECK_THROWS_AS(broken.run(p), lexe::IsolationError);
}

} // TEST_SUITE("isolation")

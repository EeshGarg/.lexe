// What a native launch is allowed to SPEND, as opposed to what it produces.
//
// This file exists because a performance defect hid for an entire wave behind
// tests that only ever asked whether things worked. A launch took 1.8 seconds
// on the development host and every lane was green, because nothing asserted
// anything about cost. It was found by an independent tester measuring the
// command out of curiosity, not by the suite.
//
// The assertions here are deliberately NOT wall-clock budgets. A timing
// assertion on a shared machine is the flakiest kind of test there is -- one
// already cost this suite three false failures in the acceptance lane. What is
// asserted instead is the WORK: that a launch which cannot use a compatibility
// runtime does not go looking for one. That is a property of the code, it is
// stable under load, and it is what actually regressed.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/runtime/execpolicy.hpp"
#include "lexe/state/appconfig.hpp"

#include <string>
#include <vector>

using namespace lexe;

namespace {

Manifest native_manifest() {
    Manifest m;
    m.id = "com.example.native";
    m.version = "1.0.0";
    m.role = PackageRole::Application;
    m.application_kind = ApplicationType::Native;
    m.architectures = {"x86_64", "aarch64"};
    return m;
}

} // namespace

TEST_SUITE("launch-cost") {

TEST_CASE("a native launch does not go looking for emulators") {
    // THE regression. `probe_providers()` searches every directory on PATH for
    // qemu-x86_64, proton, box64 and FEXInterpreter. A launch called it
    // unconditionally, including for a plain native application that can never
    // use any of them.
    //
    // On the development host that was 1.4 of the 1.8 seconds a launch took:
    // PATH under WSL carries several dozen Windows directories, each stat there
    // costs milliseconds, and a trace showed 784 failed newfstatat calls hunting
    // for interpreters that were never going to be used. After the fix the same
    // launch measured 35ms.
    //
    // The cost is real on any host; it is merely cheaper where PATH is short.
    const HostFacts host = detect_host();
    AppConfig config;

    Manifest m = native_manifest();
    REQUIRE(std::find(m.architectures.begin(), m.architectures.end(), host.isa) !=
            m.architectures.end());
    CHECK(native_launch_is_certain(m, config, host));
}

TEST_CASE("and the predicate refuses whenever a chain might matter") {
    // Conservative by construction: a wrong answer here must cost performance,
    // never correctness. Every case below falls through to the full probe.
    const HostFacts host = detect_host();

    SUBCASE("a Windows payload is never native") {
        Manifest m = native_manifest();
        m.application_kind = ApplicationType::Windows;
        m.allowed_chains = {"wine"};
        CHECK_FALSE(native_launch_is_certain(m, AppConfig{}, host));
    }

    SUBCASE("a package that does not permit the native chain") {
        Manifest m = native_manifest();
        m.allowed_chains = {"wine", "proton"};
        REQUIRE_FALSE(m.chain_allowed("native"));
        CHECK_FALSE(native_launch_is_certain(m, AppConfig{}, host));
    }

    SUBCASE("a host whose ISA the package does not name") {
        Manifest m = native_manifest();
        m.architectures = {"s390x"};
        CHECK_FALSE(native_launch_is_certain(m, AppConfig{}, host));
    }

    SUBCASE("a manual preference, whatever it names") {
        // Not inspected: §10 lets a manual preference reorder the usable set, so
        // the presence of one is enough to need the full picture. Checked even
        // for a preference that names `native`, because being cheap and
        // conservative beats being clever at a decision point like this.
        Manifest m = native_manifest();
        AppConfig config;
        config.compatibility_mode = CompatibilityMode::Manual;
        config.preferred_chain = {"native"};
        CHECK_FALSE(native_launch_is_certain(m, config, host));

        config.preferred_chain = {"proton"};
        CHECK_FALSE(native_launch_is_certain(m, config, host));
    }

    SUBCASE("a non-Linux host") {
        Manifest m = native_manifest();
        HostFacts other = host;
        other.os = "windows";
        CHECK_FALSE(native_launch_is_certain(m, AppConfig{}, other));
    }
}

TEST_CASE("an automatic preference is still the cheap path") {
    // The default. `CompatibilityMode::Automatic` with no stored preference is
    // what every application has until somebody runs `lexe compat --set`, so if
    // this were false the optimisation would apply to nothing.
    const HostFacts host = detect_host();
    AppConfig config;
    config.compatibility_mode = CompatibilityMode::Automatic;
    config.preferred_chain = {"proton"}; // stale, and ignored in Automatic mode
    CHECK(native_launch_is_certain(native_manifest(), config, host));
}

} // TEST_SUITE

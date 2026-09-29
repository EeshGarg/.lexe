// What `lexe install` SAYS it did, when it healed an interrupted install on
// the way in.
//
// `Installer::install` opens by calling `recover_locked(id)` under the mutation
// lock, so an install interrupted at or after promotion is completed forward
// before the new request is considered. That is good behaviour and it is the
// point of the transaction journal.
//
// Then, a few dozen lines later, it finds the requested version already current
// and throws BusyError with:
//
//     "<id> <version> is already installed and current"
//     hint: "Nothing was changed because nothing needed to be."
//
// Both halves are false in this case. Something WAS changed, by this very
// invocation: the pending transaction was completed and the application went
// from "interrupted, not usable" to "installed and current". The exit code says
// the operation conflicted with existing state; the hint says the caller's work
// was redundant. Neither describes what happened.
//
// An evidence audit hit this from the other side, while trying to test
// interrupted operations: after SIGKILLing a first install, `lexe list` reported
// no applications installed, and `lexe install <same package>` then exited 6
// saying it was "already installed and current". The end state was right and the
// healing was good; the account of it was wrong.
//
// This matters beyond wording because exit 6 is now a documented, load-bearing
// distinction (docs/ERRORS.md §6): 6 means the requested state ALREADY held and
// this call did nothing. A provisioning script that treats 6 as "no action
// taken, nothing to log" is being told the opposite of the truth precisely when
// the runtime has just repaired an interrupted install -- the one occasion worth
// logging.
//
// ERRORS.md §7 practice 2 governs the test itself: asserting only the healed
// case would pass against a build that never reports a conflict at all, which
// would break the genuine already-current behaviour that exit 6 exists for. So
// both are asserted in the same case, and the load-bearing assertion is that
// they DIFFER.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/error.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/base/util.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/install/transaction.hpp"
#include "lexe/package/package.hpp"
#include "lexe/state/registry.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

const char* kId = "com.example.heal";

/// Sets LEXE_TEST_FAULT for its lifetime, as test_crash_recovery.cpp does.
struct ScopedFault {
    explicit ScopedFault(const char* site) { util::set_env("LEXE_TEST_FAULT", site); }
    ~ScopedFault() { util::unset_env("LEXE_TEST_FAULT"); }
};

fs::path build_pkg(const fs::path& work, const crypto::KeyPair& key,
                   const std::string& version) {
    test::TestAppSpec spec;
    spec.id = kId;
    spec.version = version;
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree =
        test::make_test_app_tree(work / ("tree-" + version), spec);
    PackageWriter::Inputs in;
    in.payload_dir = tree.payload_dir;
    in.manifest_file = tree.manifest_file;
    const fs::path out = work / (kId + std::string("-") + version + ".lexe");
    PackageWriter::write(in, key, out);
    return out;
}

} // namespace

TEST_SUITE("install_reporting") {

TEST_CASE("an install that heals an interrupted one does not report that "
          "nothing happened") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = build_pkg(work, key, "1.0.0");

    // Crash after promotion: the version and its metadata are on disk, the
    // journal says so, and recovery will complete it forward. This is the
    // state a SIGKILLed install leaves.
    {
        ScopedFault fault("after-promote");
        CHECK_THROWS(Installer(paths).install(pkg, InstallOptions{}));
    }
    REQUIRE(read_journal(paths, kId).phase != TxnPhase::None);
    REQUIRE_FALSE(Registry(paths).is_installed(kId));

    SUBCASE("the healing install succeeds rather than reporting a conflict") {
        // This call does the work: recover_locked completes the transaction,
        // and the application becomes installed and current because of it.
        const InstallResult r = Installer(paths).install(pkg, InstallOptions{});

        CHECK(r.id == kId);
        CHECK(r.version == "1.0.0");
        CHECK(Registry(paths).is_installed(kId));
        CHECK(Registry(paths).current_version(kId) == "1.0.0");
        CHECK(read_journal(paths, kId).phase == TxnPhase::None);
    }

    SUBCASE("a genuinely redundant install still reports a conflict") {
        // The control, and it is what keeps the subcase above honest: without
        // it, a build that simply never raised BusyError would pass. Heal
        // first, so the second call really does find the state already held
        // and really did nothing.
        Installer(paths).install(pkg, InstallOptions{});
        REQUIRE(Registry(paths).is_installed(kId));

        CHECK_THROWS_AS(Installer(paths).install(pkg, InstallOptions{}),
                        BusyError);
    }
}

} // TEST_SUITE("install_reporting")

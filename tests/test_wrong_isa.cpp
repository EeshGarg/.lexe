// The wrong-ISA negative: a VALID ELF that is not this machine's ELF.
//
// `hostbuild.cpp` refuses a build product whose `e_machine` is not the host's,
// with "host-ISA compilation must produce a binary for the machine it is
// installed on". That refusal had no test. It is the check that separates
// "this is a well-formed executable" from "this is an executable THIS MACHINE
// can run", and those are different claims -- a package that cross-compiled by
// accident produces a perfectly valid ELF that cannot execute here.
//
// HOW THE SPECIMEN IS MADE, AND WHY NOT ANY OTHER WAY.
//
// The obvious construction -- synthesize an AArch64 ELF with the test helpers
// -- would pass this test for the WRONG REASON. hostbuild checks, in order:
//
//   1. is it an ELF object at all
//   2. does it have a program interpreter          <-- synthesized ELFs do not
//   3. is its e_machine the host's                 <-- the check under test
//
// A synthesized ELF is rejected at step 2 and never reaches step 3, so the
// test would go green while proving nothing about ISA. That is precisely the
// "a check cannot detect what it holds constant" failure: the interpreter
// would be the thing silently doing the work.
//
// So the specimen is a REAL host binary with exactly ONE field changed:
// `e_machine` is rewritten to EM_AARCH64. Everything else -- the interpreter,
// the program headers, the sections -- is whatever the host toolchain
// produced. The only thing that can make the two differ is the ISA field,
// which is the property under test.
//
// AND THE CONTROL IS NOT OPTIONAL. The same package shape, built the same way,
// shipping the UNPATCHED binary, must INSTALL. Without it this test passes
// against a runtime that refuses every portable build, which would look like a
// working ISA check and be a total outage.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/error.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/base/util.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/package/package.hpp"
#include "lexe/sandbox/isolation.hpp"
#include "lexe/state/registry.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#ifndef _WIN32

namespace fs = std::filesystem;
using namespace lexe;

namespace {

/// Offset of e_machine in an ELF header (ELF32 and ELF64 agree here), and the
/// value for AArch64.
constexpr std::size_t kEMachineOffset = 18;
constexpr std::uint16_t kEmAarch64 = 183;
constexpr std::uint16_t kEmX8664 = 62;

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

/// Copy `from` to `to`, rewriting e_machine. Returns the ORIGINAL value, so a
/// caller can assert it actually changed something.
std::uint16_t copy_with_machine(const fs::path& from, const fs::path& to,
                                std::uint16_t machine) {
    std::vector<std::uint8_t> bytes = util::slurp(from);
    REQUIRE(bytes.size() > kEMachineOffset + 1);
    const std::uint16_t was = static_cast<std::uint16_t>(
        bytes[kEMachineOffset] | (bytes[kEMachineOffset + 1] << 8));
    bytes[kEMachineOffset] = static_cast<std::uint8_t>(machine & 0xff);
    bytes[kEMachineOffset + 1] = static_cast<std::uint8_t>((machine >> 8) & 0xff);
    fs::create_directories(to.parent_path());
    util::spit(to, std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                    bytes.size()));
    return was;
}

} // namespace

TEST_SUITE("wrong_isa") {

TEST_CASE("a build product for another ISA is refused, and a host one is not") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    if (!test::have_native_compiler()) {
        MESSAGE("SKIP: no host C compiler, so there is no real binary to "
                "mutate and nothing to compare against");
        return;
    }
    // The ISA check runs on a build PRODUCT, and a build runs only inside the
    // sandbox (hostbuild fails closed without one). With no working isolation
    // backend both subcases would be refused for that reason instead -- the
    // control would fail and the negative would "pass" for the wrong one.
    if (make_isolation_backend(paths)->capabilities().status !=
        CapabilityStatus::Available) {
        MESSAGE("BLOCKED: no working isolation backend on this host, so no "
                "build runs and the ISA check on its product cannot be reached");
        return;
    }
    const fs::path work = home.path() / "work";
    fs::create_directories(work);

    // A real, host-native, fully-formed executable: interpreter and all.
    const fs::path real = work / "real-host-binary";
    test::write_native_executable(real, "hello from the host");
    REQUIRE(fs::exists(real));

    // The foreign ISA is the OTHER of the two this project runs on: an x86-64
    // host gets an AArch64 specimen, an AArch64 host an x86-64 one. Hard-coding
    // x86-64 as "the host" made this test fail on the AArch64 worker for a
    // reason that had nothing to do with the runtime.
    const fs::path foreign = work / "foreign-isa";
    const std::vector<std::uint8_t> real_bytes = util::slurp(real);
    REQUIRE(real_bytes.size() > kEMachineOffset + 1);
    const std::uint16_t host_machine = static_cast<std::uint16_t>(
        real_bytes[kEMachineOffset] | (real_bytes[kEMachineOffset + 1] << 8));
    REQUIRE((host_machine == kEmX8664 || host_machine == kEmAarch64));
    const std::uint16_t other =
        host_machine == kEmX8664 ? kEmAarch64 : kEmX8664;
    const std::uint16_t was = copy_with_machine(real, foreign, other);

    // The mutation must have CHANGED something, and the host must actually be
    // the ISA we think it is -- otherwise "refused" below could mean anything.
    REQUIRE(was == host_machine);
    REQUIRE(was != other);
    REQUIRE(fs::file_size(foreign) == fs::file_size(real));

    const crypto::KeyPair key = test::make_keypair();

    // Build a package whose "build" is a copy of a file already in the payload.
    // The recipe succeeds; what it PRODUCES is the thing under test.
    const auto package_shipping = [&](const std::string& id,
                                      const fs::path& payload_binary) {
        test::PortableAppSpec spec;
        spec.id = id;
        spec.command = {"cp", "src/shipped.bin", "bin/app"};
        spec.toolchain = {"cp"};
        spec.public_key = test::encode_public_key_str(key.public_key);
        const test::TestAppTree tree =
            test::make_portable_app_tree(work / ("tree-" + id), spec);
        fs::copy_file(payload_binary, tree.payload_dir / "src" / "shipped.bin",
                      fs::copy_options::overwrite_existing);
        PackageWriter::Inputs in;
        in.payload_dir = tree.payload_dir;
        in.manifest_file = tree.manifest_file;
        const fs::path out = work / (id + ".lexe");
        PackageWriter::write(in, key, out);
        return out;
    };

    InstallOptions approved;
    approved.approve_compile = true;

    SUBCASE("the control: the same shape shipping a HOST binary installs") {
        // Runs first and deliberately. If this fails, the refusal below says
        // nothing about ISA -- it would only mean portable installs are broken.
        const fs::path pkg =
            package_shipping("com.example.hostisa", real);
        Installer installer(paths);
        CHECK_NOTHROW(installer.install(pkg, approved));
        CHECK(Registry(paths).is_installed("com.example.hostisa"));
    }

    SUBCASE("a valid ELF for the other ISA is refused as a host build product") {
        const fs::path pkg =
            package_shipping("com.example.wrongisa", foreign);
        Installer installer(paths);
        try {
            installer.install(pkg, approved);
            FAIL("expected the install to be refused: the build produced a "
                 "binary for another machine");
        } catch (const Error& e) {
            const std::string msg = e.what();
            // Named specifically. "Refused" alone would also be satisfied by
            // the interpreter check, by a hash mismatch, or by the package
            // failing to verify -- none of which is this property.
            CHECK(contains(msg, "host-ISA compilation must produce a binary"));
            CHECK_FALSE(contains(msg, "not an ELF object"));
            CHECK_FALSE(contains(msg, "program interpreter"));
        }
        CHECK_FALSE(Registry(paths).is_installed("com.example.wrongisa"));
    }
}

} // TEST_SUITE("wrong_isa")

#endif // _WIN32

// ELF reader tests (Phase 2 / DX3). Crafted ELF64 images exercise the reader's
// field extraction and its defensive handling of non-ELF / truncated input. A
// real system-binary smoke test runs on Linux.

#include <doctest/doctest.h>

#include "elf_builder.hpp"

#include "core/elf.hpp"

#include <algorithm>
#include <string>
#include <vector>

using namespace lexe;

namespace {
bool has(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}
} // namespace

TEST_SUITE("elf") {

TEST_CASE("read_bytes extracts class/type/machine/interp/dynamic fields") {
    test::ElfSpec spec;
    spec.e_type = 3;      // ET_DYN
    spec.e_machine = 62;  // x86_64
    spec.interp = "/lib64/ld-linux-x86-64.so.2";
    spec.soname = "libself.so.1";
    spec.needed = {"libc.so.6", "libfoo.so.1"};
    spec.runpath = {"$ORIGIN/lib", "/opt/app/lib"};
    spec.version_needs = {"GLIBC_2.34", "GLIBC_2.17"};
    const std::vector<std::uint8_t> bytes = test::build_elf(spec);

    const elf::ElfInfo info = elf::read_bytes(bytes.data(), bytes.size());
    CHECK(info.is_elf);
    CHECK(info.elf_class == elf::Class::Elf64);
    CHECK(info.little_endian);
    CHECK(info.type == elf::Type::SharedObject);
    CHECK(info.machine == elf::Machine::X86_64);
    CHECK(info.arch() == "x86_64");
    CHECK(info.is_dynamic);
    CHECK(info.has_interpreter);
    CHECK(info.interpreter == "/lib64/ld-linux-x86-64.so.2");
    CHECK(info.soname == "libself.so.1");
    CHECK(info.needed == std::vector<std::string>{"libc.so.6", "libfoo.so.1"});
    CHECK(info.runpath == std::vector<std::string>{"$ORIGIN/lib", "/opt/app/lib"});
    CHECK(has(info.version_needs, "GLIBC_2.34"));
    CHECK(has(info.version_needs, "GLIBC_2.17"));
    CHECK(info.dynamically_linked());
}

TEST_CASE("architecture strings map correctly, including riscv width") {
    test::ElfSpec a;
    a.e_machine = 183; // aarch64
    CHECK(elf::read_bytes(test::build_elf(a).data(), test::build_elf(a).size())
              .arch() == "aarch64");

    test::ElfSpec r;
    r.e_machine = 243; // riscv (64-bit class → riscv64)
    const auto rbytes = test::build_elf(r);
    CHECK(elf::read_bytes(rbytes.data(), rbytes.size()).arch() == "riscv64");

    test::ElfSpec x;
    x.e_machine = 3; // i386 — no .lexe arch id
    const auto xbytes = test::build_elf(x);
    CHECK(elf::read_bytes(xbytes.data(), xbytes.size()).arch().empty());
}

TEST_CASE("a static (no PT_INTERP) object is not dynamically linked") {
    test::ElfSpec spec;
    spec.interp.clear();
    spec.needed = {"libc.so.6"};
    const auto bytes = test::build_elf(spec);
    const elf::ElfInfo info = elf::read_bytes(bytes.data(), bytes.size());
    CHECK(info.is_elf);
    CHECK_FALSE(info.has_interpreter);
    CHECK_FALSE(info.dynamically_linked());
    // The dynamic table is still parsed.
    CHECK(has(info.needed, "libc.so.6"));
}

TEST_CASE("non-ELF and truncated input never crash and never over-read") {
    const std::string junk = "this is definitely not an ELF file at all!!";
    const elf::ElfInfo j = elf::read_bytes(
        reinterpret_cast<const std::uint8_t*>(junk.data()), junk.size());
    CHECK_FALSE(j.is_elf);

    // A buffer shorter than an ELF header is rejected outright.
    const std::uint8_t stub[8] = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0};
    CHECK_FALSE(elf::read_bytes(stub, sizeof(stub)).is_elf);

    // Header-sized but otherwise empty (magic + class/data only, no program
    // headers): recognised as ELF, but nothing more is read — and no crash.
    std::vector<std::uint8_t> header(128, 0);
    header[0] = 0x7f; header[1] = 'E'; header[2] = 'L'; header[3] = 'F';
    header[4] = 2; header[5] = 1; header[6] = 1;
    const elf::ElfInfo t = elf::read_bytes(header.data(), header.size());
    CHECK(t.is_elf);
    CHECK(t.elf_class == elf::Class::Elf64);
    CHECK(t.needed.empty());

    // Empty / null.
    CHECK_FALSE(elf::read_bytes(nullptr, 0).is_elf);
}

#ifndef _WIN32
TEST_CASE("reads a real system binary" * doctest::may_fail()) {
    // Smoke test against the host loader/libc: at least one should parse as a
    // dynamically linked ELF with DT_NEEDED entries. may_fail() keeps this
    // non-fatal on unusual hosts.
    for (const char* path : {"/bin/sh", "/usr/bin/env", "/bin/ls"}) {
        const elf::ElfInfo info = elf::read(path);
        if (info.is_elf && info.is_dynamic) {
            CHECK(info.machine != elf::Machine::Unknown);
            return;
        }
    }
}
#endif

} // TEST_SUITE("elf")

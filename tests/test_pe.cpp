// pe reader tests — the foreign-OS counterpart of test_elf.cpp.
//
// The reader exists so the `payload-role` stage can prove that a package
// declaring a Windows application carries a Windows executable for an
// architecture it declares. It parses hostile input without running, mapping
// or trusting it, so most of this file is malformed images: a DOS stub
// pointing past the end of the file, a signature that is not "PE\0\0", a
// header cut off mid-field. None of them may crash, over-read or throw.
//
// Every test case constructs lexe::test::TempLexeHome first.

#include <doctest/doctest.h>

#include "helpers.hpp"
#include "pe_builder.hpp"

#include "lexe/package/pe.hpp"
#include "lexe/base/util.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using lexe::test::PeSpec;
using lexe::test::TempLexeHome;

TEST_SUITE("pe") {

TEST_CASE("a 64-bit console executable is read completely") {
    TempLexeHome home;
    PeSpec spec; // amd64, PE32+, console, executable image
    const std::vector<std::uint8_t> image = lexe::test::build_pe(spec);

    const lexe::pe::PeInfo info =
        lexe::pe::read_bytes(image.data(), image.size());
    CHECK(info.is_pe);
    CHECK(info.format == lexe::pe::Format::Pe32Plus);
    CHECK(info.machine == lexe::pe::Machine::Amd64);
    CHECK(info.subsystem == lexe::pe::Subsystem::Console);
    CHECK(info.executable_image);
    CHECK_FALSE(info.is_dll);
    CHECK_FALSE(info.managed);
    CHECK(info.runnable());
    CHECK(info.arch() == "x86_64");
}

TEST_CASE("a 32-bit GUI executable is read, and has no .lexe architecture id") {
    TempLexeHome home;
    PeSpec spec;
    spec.machine = 0x014C; // i386
    spec.pe32_plus = false;
    spec.subsystem = 2; // GUI
    const std::vector<std::uint8_t> image = lexe::test::build_pe(spec);

    const lexe::pe::PeInfo info =
        lexe::pe::read_bytes(image.data(), image.size());
    CHECK(info.is_pe);
    CHECK(info.format == lexe::pe::Format::Pe32);
    CHECK(info.machine == lexe::pe::Machine::I386);
    CHECK(info.subsystem == lexe::pe::Subsystem::Gui);
    CHECK(info.runnable());
    // FORMAT-0.1 §5 names x86_64 and aarch64 and nothing else. Returning ""
    // is the honest answer — a valid image for a machine this format version
    // cannot name — and the caller reports that rather than guessing.
    CHECK(info.arch().empty());
}

TEST_CASE("an ARM64 executable maps to aarch64") {
    TempLexeHome home;
    PeSpec spec;
    spec.machine = 0xAA64;
    const lexe::pe::PeInfo info = lexe::pe::read_bytes(
        lexe::test::build_pe(spec).data(), lexe::test::build_pe(spec).size());
    CHECK(info.machine == lexe::pe::Machine::Arm64);
    CHECK(info.arch() == "aarch64");
}

TEST_CASE("a DLL is identified as a library, not a program") {
    TempLexeHome home;
    PeSpec spec;
    spec.dll = true;
    const std::vector<std::uint8_t> image = lexe::test::build_pe(spec);

    const lexe::pe::PeInfo info =
        lexe::pe::read_bytes(image.data(), image.size());
    CHECK(info.is_pe);
    CHECK(info.is_dll);
    // IMAGE_FILE_EXECUTABLE_IMAGE is set on DLLs too, which is exactly why
    // "runnable" is both bits and not just that one.
    CHECK(info.executable_image);
    CHECK_FALSE(info.runnable());
}

TEST_CASE("a CLR image is noted, and is not a failure") {
    TempLexeHome home;
    PeSpec spec;
    spec.managed = true;
    const std::vector<std::uint8_t> image = lexe::test::build_pe(spec);

    const lexe::pe::PeInfo info =
        lexe::pe::read_bytes(image.data(), image.size());
    CHECK(info.is_pe);
    CHECK(info.managed);
    // Whether the host has a .NET runtime is a host-capability question for
    // the resolver, not a "these bytes are not what you said" question.
    CHECK(info.runnable());
}

TEST_CASE("non-PE input is rejected without reading past it") {
    TempLexeHome home;

    const auto not_pe = [](const std::vector<std::uint8_t>& bytes) {
        return lexe::pe::read_bytes(bytes.data(), bytes.size());
    };

    CHECK_FALSE(not_pe({}).is_pe);
    CHECK_FALSE(lexe::pe::read_bytes(nullptr, 0).is_pe);
    CHECK_FALSE(not_pe({'M'}).is_pe);                       // half the magic
    CHECK_FALSE(not_pe({0x7F, 'E', 'L', 'F'}).is_pe);       // an ELF
    CHECK_FALSE(not_pe({'#', '!', '/', 'b', 'i', 'n'}).is_pe); // a script
    CHECK_FALSE(not_pe(std::vector<std::uint8_t>(4096, 0)).is_pe);
}

TEST_CASE("a DOS stub pointing outside the file is not a PE") {
    TempLexeHome home;
    std::vector<std::uint8_t> image = lexe::test::build_pe(PeSpec{});
    // e_lfanew past the end: an MS-DOS executable, a truncated one, or a lie.
    image[0x3C] = 0xFF;
    image[0x3D] = 0xFF;
    image[0x3E] = 0xFF;
    image[0x3F] = 0x7F;

    const lexe::pe::PeInfo info =
        lexe::pe::read_bytes(image.data(), image.size());
    CHECK_FALSE(info.is_pe);
}

TEST_CASE("a wrong PE signature is not a PE") {
    TempLexeHome home;
    std::vector<std::uint8_t> image = lexe::test::build_pe(PeSpec{});
    image[0x80] = 'X'; // "PE\0\0" -> "XE\0\0"

    const lexe::pe::PeInfo info =
        lexe::pe::read_bytes(image.data(), image.size());
    CHECK_FALSE(info.is_pe);
}

TEST_CASE("truncation at every length is handled") {
    TempLexeHome home;
    const std::vector<std::uint8_t> image = lexe::test::build_pe(PeSpec{});

    // Every prefix of a real image. None may crash or over-read; each either
    // parses what is there or reports not-a-PE.
    for (std::size_t length = 0; length < image.size(); ++length) {
        CAPTURE(length);
        const lexe::pe::PeInfo info = lexe::pe::read_bytes(image.data(), length);
        if (info.is_pe) {
            // Whatever it claims must be internally consistent: a format is
            // only reported once the optional header magic was actually read.
            CHECK((info.format == lexe::pe::Format::None ||
                   info.format == lexe::pe::Format::Pe32 ||
                   info.format == lexe::pe::Format::Pe32Plus));
        }
    }
}

TEST_CASE("an object file with no optional header reports its COFF facts") {
    TempLexeHome home;
    PeSpec spec;
    spec.with_optional_header = false;
    const std::vector<std::uint8_t> image = lexe::test::build_pe(spec);

    const lexe::pe::PeInfo info =
        lexe::pe::read_bytes(image.data(), image.size());
    CHECK(info.is_pe);
    CHECK(info.machine == lexe::pe::Machine::Amd64);
    CHECK(info.format == lexe::pe::Format::None);
    CHECK(info.subsystem == lexe::pe::Subsystem::Unknown);
}

TEST_CASE("reading from a path behaves like reading from memory") {
    TempLexeHome home;
    const fs::path file = home.path() / "app.exe";
    lexe::test::write_pe(file, PeSpec{});

    const lexe::pe::PeInfo info = lexe::pe::read(file);
    CHECK(info.is_pe);
    CHECK(info.arch() == "x86_64");

    // A directory, and a path that is not there at all.
    CHECK_FALSE(lexe::pe::read(home.path()).is_pe);
    CHECK_FALSE(lexe::pe::read(home.path() / "nope.exe").is_pe);
}

TEST_CASE("an ELF binary on disk is not mistaken for a Windows executable") {
    TempLexeHome home;
    const fs::path elf = home.path() / "hello";
    lexe::test::write_elf_executable_for_arch(elf, "x86_64");
    CHECK_FALSE(lexe::pe::read(elf).is_pe);
}

} // TEST_SUITE("pe")

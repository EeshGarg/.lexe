#pragma once
// A tiny PE image builder for tests: a DOS header with the "MZ" magic and an
// e_lfanew, the "PE\0\0" signature, a COFF header and an optional header with
// the data directory — just enough of a real Windows executable for the
// lexe::pe reader and the payload-role stage to parse.
//
// It is the counterpart of elf_builder.hpp, and it exists for the same reason:
// the verification stage must be testable against images that are deliberately
// wrong (a DLL, a foreign machine, a truncated header) on a machine that has no
// Windows binaries to hand.

#include "core/util.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace lexe::test {

struct PeSpec {
    std::uint16_t machine = 0x8664;         // IMAGE_FILE_MACHINE_AMD64
    bool executable_image = true;           // IMAGE_FILE_EXECUTABLE_IMAGE
    bool dll = false;                       // IMAGE_FILE_DLL
    bool pe32_plus = true;                  // 0x20b, else 0x10b
    std::uint16_t subsystem = 3;            // IMAGE_SUBSYSTEM_WINDOWS_CUI
    bool managed = false;                   // a CLR (.NET) image
    bool with_optional_header = true;
    /// Bytes of padding after the headers, so the image is not suspiciously
    /// tiny and so truncation tests have something to cut.
    std::size_t trailing_bytes = 512;
};

namespace pe_detail {

inline void put16(std::vector<std::uint8_t>& b, std::size_t off,
                  std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v & 0xff);
    b[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
}
inline void put32(std::vector<std::uint8_t>& b, std::size_t off,
                  std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        b[off + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    }
}

} // namespace pe_detail

inline std::vector<std::uint8_t> build_pe(const PeSpec& spec) {
    using namespace pe_detail;

    constexpr std::size_t kLfanew = 0x80;
    const std::size_t optional_size =
        spec.with_optional_header ? (spec.pe32_plus ? 240u : 224u) : 0u;
    const std::size_t total =
        kLfanew + 4 + 20 + optional_size + spec.trailing_bytes;

    std::vector<std::uint8_t> image(total, 0);

    // DOS header: "MZ", then e_lfanew at 0x3c. The stub in between is the
    // real thing's "This program cannot be run in DOS mode" message; zeros
    // are fine here, and nothing reads them.
    put16(image, 0, 0x5A4D);
    put32(image, 0x3C, static_cast<std::uint32_t>(kLfanew));

    // "PE\0\0"
    put32(image, kLfanew, 0x00004550);

    // COFF file header.
    const std::size_t coff = kLfanew + 4;
    put16(image, coff + 0, spec.machine);
    put16(image, coff + 2, 1); // NumberOfSections
    put16(image, coff + 16, static_cast<std::uint16_t>(optional_size));
    std::uint16_t characteristics = 0;
    if (spec.executable_image) characteristics |= 0x0002;
    if (spec.dll) characteristics |= 0x2000;
    put16(image, coff + 18, characteristics);

    if (!spec.with_optional_header) return image;

    // Optional header.
    const std::size_t optional = coff + 20;
    put16(image, optional, spec.pe32_plus ? 0x020B : 0x010B);
    put16(image, optional + 68, spec.subsystem);

    const std::size_t directory_count_off =
        optional + (spec.pe32_plus ? 108u : 92u);
    put32(image, directory_count_off, 16); // NumberOfRvaAndSizes
    if (spec.managed) {
        const std::size_t com = directory_count_off + 4 + (14 * 8);
        put32(image, com, 0x2000);   // RVA
        put32(image, com + 4, 0x48); // size
    }
    return image;
}

inline void write_pe(const std::filesystem::path& dest, const PeSpec& spec) {
    const std::vector<std::uint8_t> image = build_pe(spec);
    if (dest.has_parent_path()) {
        std::filesystem::create_directories(dest.parent_path());
    }
    util::spit(dest, image);
}

} // namespace lexe::test

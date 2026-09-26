#pragma once
// pe — a small, bounds-checked PE/COFF metadata reader, the foreign-OS
// counterpart of core/elf.hpp.
//
// It exists for one job: the `payload-role` verification stage (FORMAT-0.1
// §6.7) must be able to prove that a package declaring a WINDOWS application
// actually carries a Windows executable for an architecture it declares —
// before anything is installed, and without running anything. The alpha's
// defining bug was a manifest that described bytes it had never been checked
// against; a foreign-OS payload type would reintroduce it exactly, one
// operating system over, if the bytes went unexamined.
//
// Like the ELF reader it parses the structures DIRECTLY. It never shells out,
// never loads the image, and never executes it. Every read is offset- and
// length-checked; a truncated or malformed file yields `is_pe = false` or
// best-effort partial info, and never throws for bad content.

#include <cstdint>
#include <filesystem>
#include <string>

namespace lexe::pe {

/// Optional-header magic: which PE variant this is.
enum class Format {
    None,
    Pe32,     // 0x10b — 32-bit
    Pe32Plus, // 0x20b — 64-bit
};

/// The subset of IMAGE_FILE_MACHINE values we name; others map to Unknown.
enum class Machine {
    Unknown,
    I386,    // IMAGE_FILE_MACHINE_I386    0x014c
    Amd64,   // IMAGE_FILE_MACHINE_AMD64   0x8664
    Arm,     // IMAGE_FILE_MACHINE_ARMNT   0x01c4
    Arm64,   // IMAGE_FILE_MACHINE_ARM64   0xaa64
    Ia64,    // IMAGE_FILE_MACHINE_IA64    0x0200
};

/// IMAGE_SUBSYSTEM, for the values that decide how a program presents itself.
enum class Subsystem {
    Unknown,
    Native,  // 1
    Gui,     // 2 — IMAGE_SUBSYSTEM_WINDOWS_GUI
    Console, // 3 — IMAGE_SUBSYSTEM_WINDOWS_CUI
    Other,
};

const char* to_string(Machine m);
const char* to_string(Subsystem s);
const char* to_string(Format f);

/// The FORMAT-0.1 §5 architecture string for a PE machine, or "" when the
/// machine has no recognised `.lexe` architecture id.
std::string arch_string(Machine m);

/// Everything the verification stage reads from one PE image.
struct PeInfo {
    bool is_pe = false;   // "MZ" … "PE\0\0" both found and in range
    Format format = Format::None;
    Machine machine = Machine::Unknown;
    Subsystem subsystem = Subsystem::Unknown;
    /// IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) — the image is runnable rather
    /// than an object file or a broken link.
    bool executable_image = false;
    /// IMAGE_FILE_DLL (0x2000) — a library, not a program. A package whose
    /// entrypoint is a DLL declares something nothing can launch.
    bool is_dll = false;
    /// A .NET/CLR image (the COM descriptor data directory is present). Noted
    /// because it needs a runtime the host may not have; NOT treated as a
    /// verification failure, since that is a host-capability question the
    /// resolver answers, not a "these bytes are not what you said" question.
    bool managed = false;

    /// The §5 architecture string of this image ("" when unrecognised).
    std::string arch() const { return arch_string(machine); }
    /// Runnable: an executable image that is not a library.
    bool runnable() const { return executable_image && !is_dll; }
};

/// Parse PE metadata from `file`. Never throws for a non-PE, truncated or
/// malformed file — returns is_pe=false, or best-effort partial info.
PeInfo read(const std::filesystem::path& file);

/// Parse PE metadata from an in-memory image (tests, in-archive scanning).
PeInfo read_bytes(const std::uint8_t* data, std::size_t size);

} // namespace lexe::pe

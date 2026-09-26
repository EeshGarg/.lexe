#pragma once
// elf — a small, bounds-checked ELF metadata reader (Phase 2 / DX3). It reads
// the fields the dependency engine needs — class, byte order, type, machine,
// the program interpreter, and the dynamic linking info (DT_NEEDED, DT_SONAME,
// DT_RPATH, DT_RUNPATH) plus versioned symbol requirements (DT_VERNEED, e.g.
// "GLIBC_2.34") — DIRECTLY from the ELF structures.
//
// It deliberately does NOT shell out to `ldd`/`readelf`: `ldd` may execute the
// binary's loader, and text parsing of external tools is fragile and
// security-sensitive. Every read is offset- and length-checked against the file
// size; a malformed or truncated file yields best-effort partial info and never
// crashes, over-reads, or throws for bad content.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace lexe::elf {

enum class Class { None, Elf32, Elf64 };

enum class Type { Unknown, Relocatable, Executable, SharedObject, Core };

/// The subset of e_machine values we name; others map to Unknown.
enum class Machine {
    Unknown,
    X86,      // EM_386
    X86_64,   // EM_X86_64
    Arm,      // EM_ARM
    AArch64,  // EM_AARCH64
    RiscV,    // EM_RISCV (width tells 32 vs 64)
    Ppc64,    // EM_PPC64
    Mips,     // EM_MIPS
    S390,     // EM_S390
};

const char* to_string(Type t);
const char* to_string(Machine m);

/// The FORMAT-0.1 §5 architecture string for a machine+class, or "" when the
/// machine has no recognised .lexe architecture id. RISC-V resolves to
/// "riscv64" only for the 64-bit class.
std::string arch_string(Machine m, Class c);

/// Everything the dependency engine reads from one ELF object.
struct ElfInfo {
    bool is_elf = false;             // magic matched
    Class elf_class = Class::None;
    bool little_endian = true;
    Type type = Type::Unknown;
    Machine machine = Machine::Unknown;
    bool is_dynamic = false;         // has a PT_DYNAMIC segment
    bool has_interpreter = false;    // has a PT_INTERP (i.e. dynamically linked)
    std::string interpreter;         // the program interpreter path, if any
    std::string soname;              // DT_SONAME, "" if none
    std::vector<std::string> needed; // DT_NEEDED sonames, in order
    std::vector<std::string> rpath;  // DT_RPATH entries (':'-split), deprecated
    std::vector<std::string> runpath;// DT_RUNPATH entries (':'-split)
    /// Versioned symbol requirements from DT_VERNEED, e.g. "GLIBC_2.34",
    /// "GLIBCXX_3.4.29". Deduplicated, in discovery order.
    std::vector<std::string> version_needs;

    /// The §5 architecture string of this object ("" when unrecognised).
    std::string arch() const { return arch_string(machine, elf_class); }
    /// A dynamically linked executable/PIE has both an interpreter and DYNAMIC.
    bool dynamically_linked() const { return has_interpreter && is_dynamic; }
};

/// Parse ELF metadata from `file`. Never throws for a non-ELF, truncated, or
/// malformed file — returns is_elf=false (not ELF) or best-effort partial info.
ElfInfo read(const std::filesystem::path& file);

/// Parse ELF metadata from an in-memory image (tests, in-archive scanning).
ElfInfo read_bytes(const std::uint8_t* data, std::size_t size);

} // namespace lexe::elf

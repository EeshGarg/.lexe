// pe — see pe.hpp. A defensive, bounds-checked reader of PE/COFF metadata.
// Every field access is validated against the buffer length; nothing here
// executes, maps, or trusts the file. Malformed input yields partial info,
// never a crash.

#include "lexe/package/pe.hpp"

#include "lexe/base/util.hpp"

#include <system_error>
#include <vector>

namespace lexe::pe {

namespace {

// --- PE constants ----------------------------------------------------------
constexpr std::uint16_t kDosMagic = 0x5A4D;      // "MZ"
constexpr std::uint32_t kPeSignature = 0x00004550; // "PE\0\0"
constexpr std::size_t kLfanewOffset = 0x3C;

constexpr std::uint16_t kMachineI386 = 0x014C;
constexpr std::uint16_t kMachineArmNt = 0x01C4;
constexpr std::uint16_t kMachineIa64 = 0x0200;
constexpr std::uint16_t kMachineAmd64 = 0x8664;
constexpr std::uint16_t kMachineArm64 = 0xAA64;

constexpr std::uint16_t kFileExecutableImage = 0x0002;
constexpr std::uint16_t kFileDll = 0x2000;

constexpr std::uint16_t kOptionalPe32 = 0x010B;
constexpr std::uint16_t kOptionalPe32Plus = 0x020B;

constexpr std::uint16_t kSubsystemNative = 1;
constexpr std::uint16_t kSubsystemGui = 2;
constexpr std::uint16_t kSubsystemConsole = 3;

/// Index of the COM descriptor (CLR header) data directory.
constexpr std::uint32_t kDirectoryComDescriptor = 14;

/// A PE header is always little-endian, so this cursor is simpler than the
/// ELF one — but it checks bounds the same way, because the file is hostile
/// input until proven otherwise.
struct Cursor {
    const std::uint8_t* p = nullptr;
    std::size_t n = 0;

    bool u16(std::size_t off, std::uint16_t& out) const {
        if (off + 2 > n) return false;
        out = static_cast<std::uint16_t>(p[off] |
                                         (static_cast<std::uint16_t>(p[off + 1])
                                          << 8));
        return true;
    }
    bool u32(std::size_t off, std::uint32_t& out) const {
        if (off + 4 > n) return false;
        out = static_cast<std::uint32_t>(p[off]) |
              (static_cast<std::uint32_t>(p[off + 1]) << 8) |
              (static_cast<std::uint32_t>(p[off + 2]) << 16) |
              (static_cast<std::uint32_t>(p[off + 3]) << 24);
        return true;
    }
};

Machine machine_from(std::uint16_t value) {
    switch (value) {
    case kMachineI386: return Machine::I386;
    case kMachineAmd64: return Machine::Amd64;
    case kMachineArmNt: return Machine::Arm;
    case kMachineArm64: return Machine::Arm64;
    case kMachineIa64: return Machine::Ia64;
    default: return Machine::Unknown;
    }
}

Subsystem subsystem_from(std::uint16_t value) {
    switch (value) {
    case kSubsystemNative: return Subsystem::Native;
    case kSubsystemGui: return Subsystem::Gui;
    case kSubsystemConsole: return Subsystem::Console;
    default: return Subsystem::Other;
    }
}

} // namespace

const char* to_string(Machine m) {
    switch (m) {
    case Machine::I386: return "i386";
    case Machine::Amd64: return "x86-64";
    case Machine::Arm: return "arm";
    case Machine::Arm64: return "arm64";
    case Machine::Ia64: return "ia64";
    case Machine::Unknown: break;
    }
    return "unknown";
}

const char* to_string(Subsystem s) {
    switch (s) {
    case Subsystem::Native: return "native";
    case Subsystem::Gui: return "gui";
    case Subsystem::Console: return "console";
    case Subsystem::Other: return "other";
    case Subsystem::Unknown: break;
    }
    return "unknown";
}

const char* to_string(Format f) {
    switch (f) {
    case Format::Pe32: return "PE32";
    case Format::Pe32Plus: return "PE32+";
    case Format::None: break;
    }
    return "none";
}

std::string arch_string(Machine m) {
    switch (m) {
    case Machine::Amd64: return "x86_64";
    case Machine::Arm64: return "aarch64";
    // i386/arm/ia64 have no FORMAT-0.1 §5 architecture id. Returning "" is the
    // honest answer: the image is a valid PE for a machine this format version
    // cannot name, which the caller reports rather than guessing at.
    case Machine::I386:
    case Machine::Arm:
    case Machine::Ia64:
    case Machine::Unknown: break;
    }
    return {};
}

PeInfo read_bytes(const std::uint8_t* data, std::size_t size) {
    PeInfo info;
    if (data == nullptr || size == 0) return info;
    const Cursor c{data, size};

    std::uint16_t dos = 0;
    if (!c.u16(0, dos) || dos != kDosMagic) return info;

    std::uint32_t lfanew = 0;
    if (!c.u32(kLfanewOffset, lfanew)) return info;
    const std::size_t pe = static_cast<std::size_t>(lfanew);
    // A DOS stub that points outside the file is not a PE image; it is an
    // MS-DOS executable, or a truncated one, or a lie.
    if (pe >= size) return info;

    std::uint32_t signature = 0;
    if (!c.u32(pe, signature) || signature != kPeSignature) return info;

    // COFF file header: machine, …, characteristics.
    const std::size_t coff = pe + 4;
    std::uint16_t machine = 0;
    std::uint16_t optional_size = 0;
    std::uint16_t characteristics = 0;
    if (!c.u16(coff + 0, machine)) return info;
    if (!c.u16(coff + 16, optional_size)) return info;
    if (!c.u16(coff + 18, characteristics)) return info;

    info.is_pe = true;
    info.machine = machine_from(machine);
    info.executable_image = (characteristics & kFileExecutableImage) != 0;
    info.is_dll = (characteristics & kFileDll) != 0;

    // An object file has no optional header at all; everything below is
    // best-effort and absence is not a parse failure.
    const std::size_t optional = coff + 20;
    if (optional_size == 0) return info;

    std::uint16_t magic = 0;
    if (!c.u16(optional, magic)) return info;
    if (magic == kOptionalPe32) {
        info.format = Format::Pe32;
    } else if (magic == kOptionalPe32Plus) {
        info.format = Format::Pe32Plus;
    } else {
        return info; // a magic we do not know: report the COFF facts only
    }
    const bool plus = info.format == Format::Pe32Plus;

    std::uint16_t subsystem = 0;
    if (c.u16(optional + 68, subsystem)) {
        info.subsystem = subsystem_from(subsystem);
    }

    // NumberOfRvaAndSizes, then the data directory array. The offsets differ
    // between PE32 and PE32+ because five fields are 8 bytes wide in PE32+.
    const std::size_t directory_count_off = optional + (plus ? 108 : 92);
    std::uint32_t directory_count = 0;
    if (!c.u32(directory_count_off, directory_count)) return info;
    if (directory_count > kDirectoryComDescriptor) {
        const std::size_t com =
            directory_count_off + 4 + (kDirectoryComDescriptor * 8);
        std::uint32_t rva = 0;
        std::uint32_t dir_size = 0;
        if (c.u32(com, rva) && c.u32(com + 4, dir_size)) {
            info.managed = rva != 0 && dir_size != 0;
        }
    }
    return info;
}

PeInfo read(const std::filesystem::path& file) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(file, ec)) return {};
    std::vector<std::uint8_t> bytes;
    try {
        bytes = util::slurp(file);
    } catch (...) {
        return {};
    }
    return read_bytes(bytes.data(), bytes.size());
}

} // namespace lexe::pe

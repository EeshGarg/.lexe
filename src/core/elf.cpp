// elf — see elf.hpp. A defensive, bounds-checked reader of ELF metadata. Every
// field access is validated against the buffer length; nothing here executes,
// maps, or trusts the file. Malformed input yields partial info, never a crash.

#include "core/elf.hpp"

#include "core/util.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace lexe::elf {

namespace {

// --- ELF constants ---------------------------------------------------------
constexpr std::uint16_t ET_REL = 1, ET_EXEC = 2, ET_DYN = 3, ET_CORE = 4;
constexpr std::uint16_t EM_386 = 3, EM_MIPS = 8, EM_PPC64 = 21, EM_S390 = 22,
                        EM_ARM = 40, EM_X86_64 = 62, EM_AARCH64 = 183,
                        EM_RISCV = 243;
constexpr std::uint32_t PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3;
// Dynamic tags (as unsigned; d_tag is signed but these positive values fit).
constexpr std::uint64_t DT_NULL = 0, DT_NEEDED = 1, DT_STRTAB = 5, DT_STRSZ = 10,
                        DT_SONAME = 14, DT_RPATH = 15, DT_RUNPATH = 29,
                        DT_VERNEED = 0x6ffffffe, DT_VERNEEDNUM = 0x6fffffff;

// Bounds against runaway loops on hostile input.
constexpr std::size_t kMaxPhnum = 4096;
constexpr std::size_t kMaxDynEntries = 1u << 16;
constexpr std::size_t kMaxVerneed = 4096;
constexpr std::size_t kMaxStr = 4096;

/// A little/big-endian integer reader that never reads out of bounds.
struct Cursor {
    const std::uint8_t* p = nullptr;
    std::size_t n = 0;
    bool le = true;

    bool u16(std::size_t off, std::uint16_t& out) const {
        if (off + 2 > n) return false;
        out = le ? static_cast<std::uint16_t>(p[off] | (p[off + 1] << 8))
                 : static_cast<std::uint16_t>(p[off + 1] | (p[off] << 8));
        return true;
    }
    bool u32(std::size_t off, std::uint32_t& out) const {
        if (off + 4 > n) return false;
        if (le) {
            out = static_cast<std::uint32_t>(p[off]) |
                  (static_cast<std::uint32_t>(p[off + 1]) << 8) |
                  (static_cast<std::uint32_t>(p[off + 2]) << 16) |
                  (static_cast<std::uint32_t>(p[off + 3]) << 24);
        } else {
            out = static_cast<std::uint32_t>(p[off + 3]) |
                  (static_cast<std::uint32_t>(p[off + 2]) << 8) |
                  (static_cast<std::uint32_t>(p[off + 1]) << 16) |
                  (static_cast<std::uint32_t>(p[off]) << 24);
        }
        return true;
    }
    bool u64(std::size_t off, std::uint64_t& out) const {
        if (off + 8 > n) return false;
        std::uint32_t lo = 0, hi = 0;
        if (le) {
            (void)u32(off, lo);
            (void)u32(off + 4, hi);
        } else {
            (void)u32(off + 4, lo);
            (void)u32(off, hi);
        }
        out = (static_cast<std::uint64_t>(hi) << 32) | lo;
        return true;
    }
    /// A word of the natural width for `is64` (used for phdr/dyn fields).
    bool word(std::size_t off, bool is64, std::uint64_t& out) const {
        if (is64) return u64(off, out);
        std::uint32_t v = 0;
        if (!u32(off, v)) return false;
        out = v;
        return true;
    }
    /// A NUL-terminated string at `off`, capped at kMaxStr and the buffer end.
    std::string cstr(std::size_t off) const {
        if (off >= n) return {};
        const std::size_t end = std::min(n, off + kMaxStr);
        std::size_t i = off;
        while (i < end && p[i] != 0) ++i;
        return std::string(reinterpret_cast<const char*>(p + off), i - off);
    }
};

Machine machine_from(std::uint16_t em) {
    switch (em) {
    case EM_386:     return Machine::X86;
    case EM_ARM:     return Machine::Arm;
    case EM_X86_64:  return Machine::X86_64;
    case EM_AARCH64: return Machine::AArch64;
    case EM_RISCV:   return Machine::RiscV;
    case EM_PPC64:   return Machine::Ppc64;
    case EM_MIPS:    return Machine::Mips;
    case EM_S390:    return Machine::S390;
    default:         return Machine::Unknown;
    }
}

Type type_from(std::uint16_t et) {
    switch (et) {
    case ET_REL:  return Type::Relocatable;
    case ET_EXEC: return Type::Executable;
    case ET_DYN:  return Type::SharedObject;
    case ET_CORE: return Type::Core;
    default:      return Type::Unknown;
    }
}

void split_colon(const std::string& s, std::vector<std::string>& out) {
    std::size_t start = 0;
    while (start <= s.size()) {
        const std::size_t sep = s.find(':', start);
        const std::string part =
            s.substr(start, sep == std::string::npos ? std::string::npos
                                                     : sep - start);
        if (!part.empty()) out.push_back(part);
        if (sep == std::string::npos) break;
        start = sep + 1;
    }
}

void push_unique(std::vector<std::string>& v, const std::string& s) {
    if (!s.empty() && std::find(v.begin(), v.end(), s) == v.end()) {
        v.push_back(s);
    }
}

} // namespace

const char* to_string(Type t) {
    switch (t) {
    case Type::Relocatable: return "relocatable";
    case Type::Executable:  return "executable";
    case Type::SharedObject:return "shared-object";
    case Type::Core:        return "core";
    case Type::Unknown:     return "unknown";
    }
    return "unknown";
}

const char* to_string(Machine m) {
    switch (m) {
    case Machine::X86:     return "x86";
    case Machine::X86_64:  return "x86_64";
    case Machine::Arm:     return "arm";
    case Machine::AArch64: return "aarch64";
    case Machine::RiscV:   return "riscv";
    case Machine::Ppc64:   return "ppc64";
    case Machine::Mips:    return "mips";
    case Machine::S390:    return "s390";
    case Machine::Unknown: return "unknown";
    }
    return "unknown";
}

std::string arch_string(Machine m, Class c) {
    switch (m) {
    case Machine::X86_64:  return "x86_64";
    case Machine::AArch64: return "aarch64";
    case Machine::RiscV:   return c == Class::Elf64 ? "riscv64" : "";
    default:               return "";
    }
}

ElfInfo read_bytes(const std::uint8_t* data, std::size_t size) {
    ElfInfo info;
    if (data == nullptr || size < 64) return info; // too short for any ELF header
    if (!(data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F')) {
        return info; // not ELF
    }
    info.is_elf = true;
    const std::uint8_t ei_class = data[4];
    const std::uint8_t ei_data = data[5];
    info.elf_class =
        ei_class == 2 ? Class::Elf64 : ei_class == 1 ? Class::Elf32 : Class::None;
    info.little_endian = ei_data != 2; // 2 == big endian
    const bool is64 = info.elf_class == Class::Elf64;

    Cursor c{data, size, info.little_endian};
    std::uint16_t e_type = 0, e_machine = 0, e_phentsize = 0, e_phnum = 0;
    c.u16(16, e_type);
    c.u16(18, e_machine);
    info.type = type_from(e_type);
    info.machine = machine_from(e_machine);
    if (info.elf_class == Class::None) return info; // fields above are stable

    std::uint64_t e_phoff = 0;
    if (is64) {
        c.u64(32, e_phoff);
        c.u16(54, e_phentsize);
        c.u16(56, e_phnum);
    } else {
        std::uint32_t off32 = 0;
        c.u32(28, off32);
        e_phoff = off32;
        c.u16(42, e_phentsize);
        c.u16(44, e_phnum);
    }
    const std::size_t min_phent = is64 ? 56 : 32;
    if (e_phentsize < min_phent || e_phnum == 0 || e_phnum > kMaxPhnum) {
        return info; // no usable program headers
    }

    // Pass 1 over the program headers: collect load segments (for vaddr→offset),
    // the dynamic segment, and the interpreter string.
    struct Segment {
        std::uint64_t vaddr = 0, off = 0, filesz = 0;
    };
    std::vector<Segment> loads;
    std::uint64_t dyn_off = 0, dyn_size = 0;
    bool have_dynamic = false;

    for (std::uint16_t i = 0; i < e_phnum; ++i) {
        const std::size_t ph = static_cast<std::size_t>(e_phoff) +
                               static_cast<std::size_t>(i) * e_phentsize;
        if (ph + min_phent > size) break;
        std::uint32_t p_type = 0;
        c.u32(ph, p_type);
        std::uint64_t p_off = 0, p_vaddr = 0, p_filesz = 0;
        if (is64) {
            c.u64(ph + 8, p_off);
            c.u64(ph + 16, p_vaddr);
            c.u64(ph + 32, p_filesz);
        } else {
            std::uint32_t o = 0, v = 0, fsz = 0;
            c.u32(ph + 4, o);
            c.u32(ph + 8, v);
            c.u32(ph + 16, fsz);
            p_off = o;
            p_vaddr = v;
            p_filesz = fsz;
        }
        if (p_type == PT_LOAD) {
            loads.push_back({p_vaddr, p_off, p_filesz});
        } else if (p_type == PT_DYNAMIC) {
            dyn_off = p_off;
            dyn_size = p_filesz;
            have_dynamic = true;
        } else if (p_type == PT_INTERP) {
            info.has_interpreter = true;
            info.interpreter = c.cstr(static_cast<std::size_t>(p_off));
        }
    }
    info.is_dynamic = have_dynamic;
    if (!have_dynamic) return info;

    const auto vaddr_to_off =
        [&](std::uint64_t vaddr, std::uint64_t& off) -> bool {
        for (const Segment& s : loads) {
            if (s.filesz == 0) continue;
            if (vaddr >= s.vaddr && vaddr - s.vaddr < s.filesz) {
                off = s.off + (vaddr - s.vaddr);
                return true;
            }
        }
        return false;
    };

    // Pass over the dynamic array: record the string table + entries of
    // interest. String values are resolved after we know DT_STRTAB.
    const std::size_t dent = is64 ? 16 : 8;
    std::uint64_t strtab_vaddr = 0, strsz = 0, soname_off = 0, verneed_vaddr = 0,
                  verneed_num = 0;
    bool have_soname = false;
    std::vector<std::uint64_t> needed_offs, rpath_offs, runpath_offs;

    const std::size_t max_entries =
        std::min<std::size_t>(kMaxDynEntries, dyn_size / dent);
    for (std::size_t i = 0; i < max_entries; ++i) {
        const std::size_t e = static_cast<std::size_t>(dyn_off) + i * dent;
        if (e + dent > size) break;
        std::uint64_t tag = 0, val = 0;
        c.word(e, is64, tag);
        c.word(e + (is64 ? 8 : 4), is64, val);
        if (tag == DT_NULL) break;
        switch (tag) {
        case DT_STRTAB:    strtab_vaddr = val; break;
        case DT_STRSZ:     strsz = val; break;
        case DT_SONAME:    soname_off = val; have_soname = true; break;
        case DT_NEEDED:    needed_offs.push_back(val); break;
        case DT_RPATH:     rpath_offs.push_back(val); break;
        case DT_RUNPATH:   runpath_offs.push_back(val); break;
        case DT_VERNEED:   verneed_vaddr = val; break;
        case DT_VERNEEDNUM:verneed_num = val; break;
        default: break;
        }
    }

    std::uint64_t strtab_off = 0;
    const bool have_strtab =
        strtab_vaddr != 0 && vaddr_to_off(strtab_vaddr, strtab_off);
    const auto str_at = [&](std::uint64_t rel) -> std::string {
        if (!have_strtab) return {};
        if (strsz != 0 && rel >= strsz) return {};
        return c.cstr(static_cast<std::size_t>(strtab_off + rel));
    };

    if (have_soname) info.soname = str_at(soname_off);
    for (std::uint64_t o : needed_offs) push_unique(info.needed, str_at(o));
    for (std::uint64_t o : rpath_offs) split_colon(str_at(o), info.rpath);
    for (std::uint64_t o : runpath_offs) split_colon(str_at(o), info.runpath);

    // Versioned symbol requirements (DT_VERNEED chain → vernaux names). These
    // names ("GLIBC_2.34", …) drive the compatibility analysis.
    if (verneed_vaddr != 0 && have_strtab) {
        std::uint64_t vn_off = 0;
        if (vaddr_to_off(verneed_vaddr, vn_off)) {
            const std::size_t limit =
                verneed_num == 0 ? kMaxVerneed
                                 : std::min<std::size_t>(kMaxVerneed, verneed_num);
            std::size_t cur = static_cast<std::size_t>(vn_off);
            for (std::size_t i = 0; i < limit; ++i) {
                if (cur + 16 > size) break;
                std::uint16_t vn_cnt = 0;
                std::uint32_t vn_aux = 0, vn_next = 0;
                c.u16(cur + 2, vn_cnt);
                c.u32(cur + 8, vn_aux);
                c.u32(cur + 12, vn_next);
                std::size_t aux = cur + vn_aux;
                const std::size_t aux_cap = std::min<std::size_t>(vn_cnt, kMaxStr);
                for (std::size_t a = 0; a < aux_cap; ++a) {
                    if (aux + 16 > size) break;
                    std::uint32_t vna_name = 0, vna_next = 0;
                    c.u32(aux + 8, vna_name);
                    c.u32(aux + 12, vna_next);
                    push_unique(info.version_needs, str_at(vna_name));
                    if (vna_next == 0) break;
                    aux += vna_next;
                }
                if (vn_next == 0) break;
                cur += vn_next;
            }
        }
    }
    return info;
}

ElfInfo read(const std::filesystem::path& file) {
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

} // namespace lexe::elf

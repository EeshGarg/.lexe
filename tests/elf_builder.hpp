#pragma once
// A tiny ELF64 (little-endian) image builder for tests: it emits just enough of
// a real ELF — header, program headers (LOAD/DYNAMIC/optional INTERP), a
// dynamic array, a string table, and an optional DT_VERNEED chain — for the
// lexe::elf reader and the dependency engine to parse. PT_LOAD uses an identity
// vaddr==offset mapping so string/verneed virtual addresses equal file offsets.

#include "core/util.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace lexe::test {

struct ElfSpec {
    std::uint16_t e_type = 3;    // ET_DYN
    std::uint16_t e_machine = 62; // EM_X86_64
    std::string interp;                       // "" = none (static)
    std::string soname;                       // "" = none
    std::vector<std::string> needed;
    std::vector<std::string> runpath;         // joined with ':'
    std::vector<std::string> version_needs;   // vernaux names, e.g. "GLIBC_2.34"
    std::string verneed_file = "libc.so.6";
};

namespace elf_detail {

inline void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off] = v & 0xff;
    b[off + 1] = (v >> 8) & 0xff;
}
inline void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = (v >> (8 * i)) & 0xff;
}
inline void put64(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + i] = (v >> (8 * i)) & 0xff;
}

} // namespace elf_detail

inline std::vector<std::uint8_t> build_elf(const ElfSpec& spec) {
    using namespace elf_detail;

    // --- string table (offset 0 is the empty string) ---
    std::string strtab(1, '\0');
    std::map<std::string, std::uint32_t> offsets;
    const auto add_str = [&](const std::string& s) -> std::uint32_t {
        if (s.empty()) return 0;
        auto it = offsets.find(s);
        if (it != offsets.end()) return it->second;
        const std::uint32_t off = static_cast<std::uint32_t>(strtab.size());
        strtab += s;
        strtab.push_back('\0');
        offsets[s] = off;
        return off;
    };
    const std::uint32_t soname_off = add_str(spec.soname);
    std::vector<std::uint32_t> needed_offs;
    for (const std::string& n : spec.needed) needed_offs.push_back(add_str(n));
    std::string runpath_joined;
    for (const std::string& r : spec.runpath) {
        if (!runpath_joined.empty()) runpath_joined += ':';
        runpath_joined += r;
    }
    const std::uint32_t runpath_off = add_str(runpath_joined);
    const std::uint32_t interp_off = add_str(spec.interp);
    const std::uint32_t vnfile_off = add_str(spec.verneed_file);
    std::vector<std::uint32_t> ver_offs;
    for (const std::string& v : spec.version_needs) ver_offs.push_back(add_str(v));

    // --- dynamic entries ---
    struct Dyn {
        std::uint64_t tag, val;
    };
    std::vector<Dyn> dyn;
    const bool has_ver = !spec.version_needs.empty();

    // --- layout ---
    const bool has_interp = !spec.interp.empty();
    const std::uint16_t phnum =
        static_cast<std::uint16_t>(2 + (has_interp ? 1 : 0)); // LOAD + DYNAMIC
    const std::size_t phoff = 64;
    const std::size_t ph_size = static_cast<std::size_t>(phnum) * 56;
    const std::size_t dyn_off = phoff + ph_size;

    const std::size_t dyn_count = 2 /*STRTAB,STRSZ*/ + spec.needed.size() +
                                  (spec.soname.empty() ? 0 : 1) +
                                  (runpath_joined.empty() ? 0 : 1) +
                                  (has_ver ? 2 : 0) + 1 /*DT_NULL*/;
    const std::size_t dyn_size = dyn_count * 16;
    const std::size_t strtab_off = dyn_off + dyn_size;
    const std::size_t verneed_off = strtab_off + strtab.size();
    const std::size_t verneed_size =
        has_ver ? (16 + spec.version_needs.size() * 16) : 0;
    const std::size_t total = verneed_off + verneed_size;

    // Now that offsets are known, populate the dynamic array (vaddr==offset).
    dyn.push_back({5, strtab_off});                 // DT_STRTAB
    dyn.push_back({10, strtab.size()});             // DT_STRSZ
    if (!spec.soname.empty()) dyn.push_back({14, soname_off}); // DT_SONAME
    for (std::uint32_t o : needed_offs) dyn.push_back({1, o}); // DT_NEEDED
    if (!runpath_joined.empty()) dyn.push_back({29, runpath_off}); // DT_RUNPATH
    if (has_ver) {
        dyn.push_back({0x6ffffffe, verneed_off});   // DT_VERNEED
        dyn.push_back({0x6fffffff, 1});             // DT_VERNEEDNUM
    }
    dyn.push_back({0, 0});                           // DT_NULL

    std::vector<std::uint8_t> b(total, 0);
    // ELF header
    b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 2; b[5] = 1; b[6] = 1; // 64-bit, LE, version 1
    put16(b, 16, spec.e_type);
    put16(b, 18, spec.e_machine);
    put32(b, 20, 1);
    put64(b, 32, phoff);          // e_phoff
    put16(b, 52, 64);             // e_ehsize
    put16(b, 54, 56);             // e_phentsize
    put16(b, 56, phnum);          // e_phnum

    // Program headers
    std::size_t ph = phoff;
    // PT_LOAD covering the whole file (identity vaddr==offset).
    put32(b, ph + 0, 1);          // p_type = PT_LOAD
    put32(b, ph + 4, 5);          // p_flags r-x
    put64(b, ph + 8, 0);          // p_offset
    put64(b, ph + 16, 0);         // p_vaddr
    put64(b, ph + 32, total);     // p_filesz
    put64(b, ph + 40, total);     // p_memsz
    ph += 56;
    // PT_DYNAMIC
    put32(b, ph + 0, 2);
    put64(b, ph + 8, dyn_off);
    put64(b, ph + 16, dyn_off);
    put64(b, ph + 32, dyn_size);
    put64(b, ph + 40, dyn_size);
    ph += 56;
    if (has_interp) {
        put32(b, ph + 0, 3);      // PT_INTERP
        const std::size_t iof = strtab_off + interp_off;
        put64(b, ph + 8, iof);
        put64(b, ph + 16, iof);
        put64(b, ph + 32, spec.interp.size() + 1);
        put64(b, ph + 40, spec.interp.size() + 1);
        ph += 56;
    }

    // Dynamic array
    for (std::size_t i = 0; i < dyn.size(); ++i) {
        put64(b, dyn_off + i * 16 + 0, dyn[i].tag);
        put64(b, dyn_off + i * 16 + 8, dyn[i].val);
    }

    // String table
    for (std::size_t i = 0; i < strtab.size(); ++i) {
        b[strtab_off + i] = static_cast<std::uint8_t>(strtab[i]);
    }

    // Verneed (one entry naming vnfile, with a vernaux per version).
    if (has_ver) {
        put16(b, verneed_off + 0, 1);                       // vn_version
        put16(b, verneed_off + 2, static_cast<std::uint16_t>(spec.version_needs.size()));
        put32(b, verneed_off + 4, vnfile_off);              // vn_file
        put32(b, verneed_off + 8, 16);                      // vn_aux (→ first aux)
        put32(b, verneed_off + 12, 0);                      // vn_next
        for (std::size_t i = 0; i < spec.version_needs.size(); ++i) {
            const std::size_t aux = verneed_off + 16 + i * 16;
            put32(b, aux + 8, ver_offs[i]);                 // vna_name
            put32(b, aux + 12,
                  i + 1 < spec.version_needs.size() ? 16 : 0); // vna_next
        }
    }
    return b;
}

/// Build an ELF image and write it to `path`.
inline std::filesystem::path write_elf(const std::filesystem::path& path,
                                       const ElfSpec& spec) {
    const std::vector<std::uint8_t> bytes = build_elf(spec);
    lexe::util::spit(path, bytes);
    return path;
}

} // namespace lexe::test

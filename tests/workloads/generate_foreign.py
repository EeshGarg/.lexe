#!/usr/bin/env python3
"""Foreign-ISA fixture factory: genuine AArch64 ELF files, made on x86-64.

WHY THIS EXISTS
    A compile stage that trusts a successful compiler invocation will happily
    hand over a binary for the wrong machine. The only way to find that out is
    to have a file that is a valid, structurally executable ELF for an ISA this
    host is not. That is what this generator manufactures.

WHAT IT PROVES, AND WHAT IT DOES NOT
    It proves that a consumer can be handed an AArch64 executable. It proves
    NOTHING WHATSOEVER about AArch64 support -- not here, not anywhere. There is
    no AArch64 kernel, no qemu-user and no cross libc on this host, so these
    fixtures CANNOT BE EXECUTED and therefore have no direct-execution baseline.
    Their baseline is structural, plus the measured refusal when this host is
    asked to run one. Any report that describes this corpus as AArch64 coverage
    is wrong.

THE LINKER SUBSTITUTE, AND WHY IT IS NOT A FORGERY
    clang here has the aarch64 target and an integrated assembler, so it emits a
    genuine AArch64 object (ELF machine 183). Nothing here can LINK one:
    measured, in this run and recorded in the index -- GNU ld has no
    `aarch64linux` emulation, ld.gold rejects "ELF machine number 183", and lld
    is not installed. gcc-aarch64-linux-gnu and lld are both in apt but
    installing them needs authorisation this role does not have.

    So this generator performs the link: it reads the .text section straight out
    of clang's object and writes an ELF header, one PT_LOAD and a minimal
    section header table around it. Every byte of code is clang's, verbatim.

    A separate wave declined to patch e_machine in a host binary, on the grounds
    that it produces a deliberately malformed ELF, which is a VERIFICATION INPUT
    and not a workload. That reasoning stands and this is the other side of it.
    The discriminating question is checkable rather than a matter of taste:

        would a correct loader on the TARGET platform run this successfully?

    Patched e_machine: no. The header would claim AArch64 over x86-64
    instructions, so no loader anywhere could run it; its only possible use is to
    see whether a checker notices an inconsistency. Hand-linked: yes. A
    Linux/AArch64 kernel loads this, jumps to the entry point, and the program
    prints its oracle and exits 0. Nothing about the machine, the instructions,
    the entry point or the segment is fabricated; the only thing missing was a
    program that writes 120 bytes of header, and for a single-section object with
    NO RELOCATIONS that is the entirety of a static linker's job.

    Two guardrails keep that claim honest, and both are enforced rather than
    asserted:

      1. ZERO RELOCATIONS. The generator fails if clang's object contains any
         relocation at all. If it did, hand-linking would mean resolving
         addresses by hand, which is a different and much weaker claim. Every
         address in the source is PC-relative for exactly this reason.
      2. THE BYTES ARE CLANG'S. The extracted .text is cross-checked against an
         independent extraction by llvm-objcopy, and the sha256 of the object,
         of the extracted .text and of the final file are all recorded, so
         anyone can re-extract and compare without trusting this script.

USAGE
    python3 generate_foreign.py --out /tmp/lexe-workloads-foreign
    Exit status 0 means every fixture reached verdict "structural-ok".
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SPECS = os.path.join(HERE, "specs_foreign")

# ELF constants used below, spelled out so nothing here is a magic number.
EM_AARCH64 = 183
EM_X86_64 = 62
ET_REL, ET_EXEC, ET_DYN = 1, 2, 3
SHT_PROGBITS, SHT_STRTAB, SHT_REL, SHT_RELA = 1, 3, 9, 4
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4
PT_LOAD = 1
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4
EHDR_SIZE, PHDR_SIZE, SHDR_SIZE = 64, 56, 64

# The one place a number is chosen rather than derived: the fixed load address of
# the non-PIE variant. 0x400000 is the conventional x86-64/AArch64 ELF text base
# and is congruent to 0 mod the 0x1000 segment alignment, which p_offset must
# match. Nothing depends on the specific value.
NONPIE_BASE = 0x400000
SEG_ALIGN = 0x1000


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def tool_version(binary):
    if shutil.which(binary) is None:
        return "ABSENT"
    p = sh([binary, "--version"])
    return (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr) else "?"


def first_present(*names):
    for n in names:
        if shutil.which(n):
            return n
    return None


# --------------------------------------------------------------------------
# A small, explicit ELF64 reader. Only what is needed, and no dependency on any
# tool that might not understand machine 183 -- binutils on this host does not.
# --------------------------------------------------------------------------

class Elf64:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if len(d) < EHDR_SIZE or d[:4] != b"\x7fELF":
            raise ValueError("not an ELF file: bad magic")
        self.ei_class, self.ei_data = d[4], d[5]
        if self.ei_class != 2 or self.ei_data != 1:
            raise ValueError("expected ELF64 little-endian, got class=%d data=%d"
                             % (self.ei_class, self.ei_data))
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
         self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
            "<HHIQQQIHHHHHH", d, 16)

    def sections(self):
        out = []
        if not self.e_shoff or not self.e_shnum:
            return out
        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            (name, typ, flags, addr, offset, size, link, info, align, entsize) = \
                struct.unpack_from("<IIQQQQIIQQ", self.data, off)
            raw.append({"name_off": name, "type": typ, "flags": flags, "addr": addr,
                        "offset": offset, "size": size, "link": link, "info": info,
                        "align": align, "entsize": entsize})
        strtab = raw[self.e_shstrndx]
        blob = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]
        for s in raw:
            end = blob.find(b"\0", s["name_off"])
            s["name"] = blob[s["name_off"]:end].decode("ascii", "replace")
            out.append(s)
        return out

    def segments(self):
        out = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (typ, flags, offset, vaddr, paddr, filesz, memsz, align) = \
                struct.unpack_from("<IIQQQQQQ", self.data, off)
            out.append({"type": typ, "flags": flags, "offset": offset, "vaddr": vaddr,
                        "paddr": paddr, "filesz": filesz, "memsz": memsz, "align": align})
        return out


# --------------------------------------------------------------------------
# The link. Header bytes only: the code is copied, never rewritten.
# --------------------------------------------------------------------------

def link_exec(text, e_type, base):
    """Wrap `text` in an ELF64 AArch64 executable with one PT_LOAD.

    Layout, all of it derived rather than chosen:

        0x0000  Ehdr                    64 bytes
        0x0040  Phdr[0] PT_LOAD R+X     56 bytes
        0x0078  .text                   len(text)      <-- e_entry points here
                .shstrtab                              not loaded
                Shdr[0..2]                             not loaded

    For ET_EXEC `base` is the fixed load address and e_entry is absolute. For
    ET_DYN `base` is 0 and e_entry is an offset from wherever the kernel loads
    the image; both are correct AArch64 Linux shapes and the code is entirely
    PC-relative, so the same bytes serve both.
    """
    text_off = EHDR_SIZE + PHDR_SIZE            # 0x78, already 8-aligned
    assert text_off % 8 == 0, "entry must respect AArch64 instruction alignment"
    entry = base + text_off
    load_filesz = text_off + len(text)

    shstr = b"\0.text\0.shstrtab\0"
    shstr_off = load_filesz
    shdr_off = (shstr_off + len(shstr) + 7) & ~7

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, EM_AARCH64, 1, entry,
        EHDR_SIZE,              # e_phoff
        shdr_off,               # e_shoff
        0,                      # e_flags
        EHDR_SIZE, PHDR_SIZE, 1,
        SHDR_SIZE, 3, 2)        # 3 section headers, .shstrtab is index 2

    phdr = struct.pack("<IIQQQQQQ", PT_LOAD, PF_R | PF_X, 0, base, base,
                       load_filesz, load_filesz, SEG_ALIGN)

    def shdr(name_off, typ, flags, addr, offset, size, align, entsize=0):
        return struct.pack("<IIQQQQIIQQ", name_off, typ, flags, addr, offset,
                           size, 0, 0, align, entsize)

    shdrs = (shdr(0, 0, 0, 0, 0, 0, 0)
             + shdr(1, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, entry, text_off,
                    len(text), 8)
             + shdr(7, SHT_STRTAB, 0, 0, shstr_off, len(shstr), 1))

    blob = bytearray()
    blob += ehdr
    blob += phdr
    assert len(blob) == text_off
    blob += text
    blob += shstr
    blob += b"\0" * (shdr_off - len(blob))
    blob += shdrs
    return bytes(blob), {"entry": entry, "base": base, "text_file_offset": text_off,
                         "load_filesz": load_filesz, "shdr_offset": shdr_off}


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

FIXTURES = [
    {
        "id": "linux-foreign-aarch64-object",
        "kind": "object",
        "property": "clang's own AArch64 relocatable object, unaltered",
        "declared": {
            "elf_class": "ELF64", "elf_data": "little-endian",
            "e_type": "REL", "e_machine": EM_AARCH64,
            "structurally_executable": False,
            "matches_host_isa": False,
            "directly_executable_here": False,
        },
        "notes":
            "The honest control, and the reason the executable below had to be "
            "made. ET_REL is not executable in structural terms, so a compile "
            "stage that checks the ELF TYPE before it checks the MACHINE will "
            "reject this for the wrong reason and never reach the architecture "
            "check at all. A test built on this file would pass while proving "
            "nothing -- which is precisely the class of defect this corpus keeps "
            "finding -- so it is kept as a labelled control and must never be "
            "used as the foreign-architecture case.",
    },
    {
        "id": "linux-foreign-aarch64-exec",
        "kind": "exec",
        "e_type": ET_EXEC,
        "base": NONPIE_BASE,
        "property": "a structurally executable non-PIE AArch64 ELF (ET_EXEC)",
        "declared": {
            "elf_class": "ELF64", "elf_data": "little-endian",
            "e_type": "EXEC", "e_machine": EM_AARCH64,
            "structurally_executable": True,
            "load_segments": 1, "entry_in_executable_segment": True,
            "matches_host_isa": False,
            "directly_executable_here": False,
            "oracle_stream_on_aarch64": [
                "FIXTURE_ID=linux-foreign-aarch64-exec",
                "ARCH_DECLARED=aarch64",
                "SYSCALL_ABI=linux-aarch64-svc0",
                "LINKED_BY=generate_foreign.py",
                "RELOCATIONS=none",
                "WROTE_ORACLE=yes",
                "RESULT=PASS",
            ],
            "oracle_stream_verified_here": False,
        },
        "notes":
            "THE fixture. It reaches an architecture check because it passes a "
            "type check first: ET_EXEC, a valid entry point, and one loadable "
            "executable segment containing it. The declared oracle stream is "
            "what it prints on a Linux/AArch64 host and is NOT verified here, "
            "because it cannot be run here; that is stated in the record rather "
            "than left to be inferred.",
    },
    {
        "id": "linux-foreign-aarch64-pie",
        "kind": "exec",
        "e_type": ET_DYN,
        "base": 0,
        "property": "a structurally executable AArch64 static PIE (ET_DYN, no interpreter)",
        "declared": {
            "elf_class": "ELF64", "elf_data": "little-endian",
            "e_type": "DYN", "e_machine": EM_AARCH64,
            "structurally_executable": True,
            "load_segments": 1, "entry_in_executable_segment": True,
            "interpreter": None,
            "matches_host_isa": False,
            "directly_executable_here": False,
            "oracle_stream_verified_here": False,
        },
        "notes":
            "The same clang bytes as a position-independent image. Free to make "
            "and a genuinely separate shape: a consumer that special-cases "
            "ET_DYN -- the default for nearly every ELF it will ever see on a "
            "modern distribution -- takes a different path to the machine check "
            "than it does for ET_EXEC. Every address in the source is "
            "PC-relative and there are no relocations, so one .text is correct "
            "at any load base and no DT_ entries are needed.",
    },
]


def assemble(out):
    """Assemble the AArch64 source. Measured facts only."""
    src = os.path.join(SPECS, "aarch64_oracle.S")
    obj = os.path.join(out, "aarch64_oracle.o")
    cmd = ["clang", "--target=aarch64-linux-gnu", "-x", "assembler-with-cpp",
           "-ffreestanding", "-c", "-o", obj, src]
    t0 = time.time()
    p = sh(cmd)
    secs = round(time.time() - t0, 3)
    rec = {"source": os.path.basename(src),
           "source_sha256": sha256_file(src),
           "command": " ".join(cmd),
           "compiler": "clang",
           "compiler_version": tool_version("clang"),
           "exit_status": p.returncode,
           "compile_ok": p.returncode == 0 and os.path.exists(obj),
           "compile_seconds": secs,
           "diagnostics": (p.stdout + p.stderr).strip()}
    if not rec["compile_ok"]:
        return rec, None, None
    rec["object"] = obj
    rec["object_sha256"] = sha256_file(obj)
    rec["object_size"] = os.path.getsize(obj)
    rec["file_says"] = sh(["file", "-b", obj]).stdout.strip()

    e = Elf64(obj)
    rec["object_e_type"] = e.e_type
    rec["object_e_machine"] = e.e_machine
    rec["object_is_aarch64"] = e.e_machine == EM_AARCH64
    rec["object_is_relocatable"] = e.e_type == ET_REL

    secs_list = e.sections()
    rec["sections"] = [{"name": s["name"], "type": s["type"], "size": s["size"],
                        "flags": s["flags"], "align": s["align"]} for s in secs_list]

    # GUARDRAIL 1: no relocations anywhere. If clang emits one, hand-linking
    # would mean resolving an address by hand, which is a weaker claim than the
    # one this corpus makes, so the fixture fails instead.
    relocs = [s["name"] for s in secs_list if s["type"] in (SHT_REL, SHT_RELA)]
    rec["relocation_sections"] = relocs
    rec["relocation_free"] = not relocs

    text = [s for s in secs_list if s["name"] == ".text"]
    if not text:
        rec["extract_ok"] = False
        rec["extract_problem"] = "no .text section in the object"
        return rec, None, None
    t = text[0]
    if not (t["flags"] & SHF_ALLOC) or not (t["flags"] & SHF_EXECINSTR):
        rec["extract_ok"] = False
        rec["extract_problem"] = ".text is not SHF_ALLOC|SHF_EXECINSTR"
        return rec, None, None
    body = e.data[t["offset"]:t["offset"] + t["size"]]
    rec["text_offset_in_object"] = t["offset"]
    rec["text_size"] = t["size"]
    rec["text_sha256"] = sha256_bytes(body)
    rec["text_align"] = t["align"]
    rec["extract_ok"] = len(body) == t["size"] and t["size"] > 0

    # GUARDRAIL 2: the bytes are clang's. An independent extraction by a tool
    # this script did not write must agree byte for byte.
    objcopy = first_present("llvm-objcopy", "llvm-objcopy-18")
    rec["independent_extractor"] = objcopy or "ABSENT"
    if objcopy:
        binp = os.path.join(out, "aarch64_oracle.text.bin")
        q = sh([objcopy, "-O", "binary", "--only-section=.text", obj, binp])
        if q.returncode == 0 and os.path.exists(binp):
            with open(binp, "rb") as f:
                alt = f.read()
            rec["independent_extraction_sha256"] = sha256_bytes(alt)
            rec["independent_extraction_agrees"] = alt == body
        else:
            rec["independent_extraction_agrees"] = None
            rec["independent_extraction_error"] = (q.stdout + q.stderr).strip()[:300]
    else:
        rec["independent_extraction_agrees"] = None

    # Provenance, not verification: a disassembly anyone can read.
    objdump = first_present("llvm-objdump", "llvm-objdump-18")
    rec["disassembler"] = objdump or "ABSENT"
    if objdump:
        d = sh([objdump, "-d", "--triple=aarch64-linux-gnu", obj])
        rec["text_disassembly"] = d.stdout.strip().splitlines()[:40]
    return rec, body, t


def probe_linkers(out):
    """Measure, do not assume, that nothing here can link machine 183."""
    obj = os.path.join(out, "aarch64_oracle.o")
    routes = []
    for label, extra in (("clang default (GNU ld)", []),
                         ("clang -fuse-ld=gold", ["-fuse-ld=gold"]),
                         ("clang -fuse-ld=lld", ["-fuse-ld=lld"])):
        target = os.path.join(out, "linkprobe.elf")
        if os.path.exists(target):
            os.remove(target)
        p = sh(["clang", "--target=aarch64-linux-gnu", "-nostdlib", "-static"]
               + extra + ["-o", target, obj])
        routes.append({"route": label, "exit_status": p.returncode,
                       "linked": p.returncode == 0 and os.path.exists(target),
                       "message": (p.stderr or p.stdout).strip().splitlines()[:1]})
    emulations = sh(["ld", "--help"]).stdout
    line = next((l.strip() for l in emulations.splitlines()
                 if "supported emulations" in l.lower()), "")
    return {"routes": routes,
            "any_route_linked": any(r["linked"] for r in routes),
            "host_ld_supported_emulations": line,
            "cross_gcc_present": shutil.which("aarch64-linux-gnu-gcc") is not None,
            "lld_present": first_present("lld", "ld.lld") is not None,
            "qemu_user_present": first_present("qemu-aarch64", "qemu-aarch64-static")
                                 is not None,
            "blocked_note":
                "gcc-aarch64-linux-gnu and lld are both available in apt. "
                "Installing either needs authorisation this role does not have, "
                "so a linker-produced AArch64 executable stays BLOCKED and the "
                "generator links the file itself instead."}


def host_facts():
    u = os.uname()
    true_bin = "/bin/true"
    host_machine = None
    try:
        host_machine = Elf64(true_bin).e_machine
    except Exception:
        pass
    return {"uname_machine": u.machine, "kernel": u.release, "sysname": u.sysname,
            "loadavg": open("/proc/loadavg").read().split()[:3],
            "host_elf_machine_from_%s" % os.path.basename(true_bin): host_machine,
            "host_elf_machine_is_x86_64": host_machine == EM_X86_64,
            "nproc": os.cpu_count()}


def try_direct_execution(path):
    """What does THIS host do when asked to run it? A measured refusal is the
    only execution fact a foreign-ISA fixture can have, and recording it is what
    distinguishes 'cannot run here' from 'was never tried'."""
    os.chmod(path, 0o755)
    rec = {"attempted": True}
    try:
        p = subprocess.run([path], capture_output=True, timeout=20)
        rec.update({"raised_oserror": False, "exit_code": p.returncode,
                    "stdout_bytes": len(p.stdout), "stderr_bytes": len(p.stderr),
                    "refused": False})
    except OSError as exc:
        rec.update({"raised_oserror": True, "errno": exc.errno,
                    "errno_name": os.strerror(exc.errno) if exc.errno else None,
                    "refused": True})
    except subprocess.TimeoutExpired:
        rec.update({"raised_oserror": False, "timed_out": True, "refused": False})
    # And through a shell, which reports it differently and is how a human meets it.
    q = sh(["/bin/sh", "-c", '"$1"', "sh", path])
    rec["shell_exit_status"] = q.returncode
    rec["shell_stderr"] = q.stderr.strip()[:200]
    return rec


def verify(fix, path, asm):
    """Every claim in `declared`, checked against the file on disk."""
    m = {"path": path, "size": os.path.getsize(path), "sha256": sha256_file(path)}
    problems = []

    # FACT 1 -- compilation succeeded.
    m["fact_compile_succeeded"] = bool(asm.get("compile_ok"))
    if not m["fact_compile_succeeded"]:
        problems.append("compilation did not succeed")

    # FACT 2 -- the output is a valid ELF. Parsed twice: by this script, and by
    # readelf, which is an independent implementation even though this host's
    # binutils cannot disassemble machine 183.
    try:
        e = Elf64(path)
        m["fact_valid_elf"] = True
    except Exception as exc:
        m["fact_valid_elf"] = False
        m["elf_parse_error"] = repr(exc)
        problems.append("not a valid ELF: %r" % (exc,))
        return m, problems
    r = sh(["readelf", "-hlSW", path])
    m["readelf_exit_status"] = r.returncode
    m["readelf_accepted"] = r.returncode == 0 and "Error" not in r.stderr
    m["readelf_header"] = [l.strip() for l in r.stdout.splitlines()
                           if any(k in l for k in ("Class:", "Data:", "Type:",
                                                   "Machine:", "Entry point",
                                                   "Version:"))]
    m["file_says"] = sh(["file", "-b", path]).stdout.strip()
    if not m["readelf_accepted"]:
        problems.append("readelf did not accept the file")

    m["elf_class"] = "ELF64" if e.ei_class == 2 else "ELF%d" % (e.ei_class,)
    m["elf_data"] = "little-endian" if e.ei_data == 1 else "big-endian"
    m["e_type"] = {ET_REL: "REL", ET_EXEC: "EXEC", ET_DYN: "DYN"}.get(e.e_type, str(e.e_type))
    m["e_machine"] = e.e_machine
    m["e_entry"] = e.e_entry
    m["e_phnum"] = e.e_phnum
    m["sections"] = [{"name": s["name"], "size": s["size"], "addr": s["addr"]}
                     for s in e.sections()]

    # FACT 3 -- the machine type is AArch64. From the raw header, and confirmed
    # in readelf's and file(1)'s own words.
    m["fact_machine_is_aarch64"] = e.e_machine == EM_AARCH64
    m["machine_named_by_readelf"] = next((l for l in m["readelf_header"]
                                         if l.startswith("Machine:")), None)
    m["machine_named_by_file"] = "aarch64" in m["file_says"].lower()
    if not m["fact_machine_is_aarch64"]:
        problems.append("e_machine is %d, not %d (AArch64)" % (e.e_machine, EM_AARCH64))

    # FACT 4 -- it is structurally executable: the right type, a non-trivial
    # entry point, and one loadable executable segment that contains it.
    segs = e.segments()
    loads = [s for s in segs if s["type"] == PT_LOAD]
    m["load_segments"] = len(loads)
    m["segments"] = [{"type": s["type"], "flags": s["flags"], "vaddr": s["vaddr"],
                      "offset": s["offset"], "filesz": s["filesz"],
                      "memsz": s["memsz"], "align": s["align"]} for s in segs]
    m["interpreter"] = None   # no PT_INTERP is emitted; recorded as a fact, not assumed
    m["has_pt_interp"] = any(s["type"] == 3 for s in segs)
    entry_seg = [s for s in loads
                 if s["vaddr"] <= e.e_entry < s["vaddr"] + s["memsz"]]
    m["entry_in_load_segment"] = bool(entry_seg)
    m["entry_segment_executable"] = bool(entry_seg) and bool(entry_seg[0]["flags"] & PF_X)
    m["entry_alignment_ok"] = e.e_entry % 4 == 0   # AArch64 instructions are 4-byte
    m["offset_vaddr_congruent"] = all(
        (s["offset"] % s["align"]) == (s["vaddr"] % s["align"]) if s["align"] else True
        for s in loads)
    declared_exec = fix["declared"]["structurally_executable"]
    m["fact_structurally_executable"] = bool(
        e.e_type in (ET_EXEC, ET_DYN) and e.e_entry != 0 and m["entry_in_load_segment"]
        and m["entry_segment_executable"] and m["entry_alignment_ok"]
        and m["offset_vaddr_congruent"])
    if m["fact_structurally_executable"] != declared_exec:
        problems.append("structurally_executable is %s, declared %s"
                        % (m["fact_structurally_executable"], declared_exec))

    # The instruction bytes at the entry point ARE the first bytes clang emitted.
    if asm.get("text_sha256") and m["fact_structurally_executable"]:
        text_off = e.e_entry - loads[0]["vaddr"] + loads[0]["offset"]
        body = e.data[text_off:text_off + asm["text_size"]]
        m["entry_text_sha256"] = sha256_bytes(body)
        m["entry_text_is_the_compiled_object_text"] = \
            m["entry_text_sha256"] == asm["text_sha256"]
        if not m["entry_text_is_the_compiled_object_text"]:
            problems.append("the bytes at the entry point are not the object's .text")

    # FACT 5 -- it does not match the host ISA, and this host refuses to run it.
    host = Elf64("/bin/true").e_machine
    m["host_elf_machine"] = host
    m["fact_differs_from_host_isa"] = e.e_machine != host
    if not m["fact_differs_from_host_isa"]:
        problems.append("e_machine equals the host's (%d): this is not a foreign "
                        "ISA fixture at all" % host)
    m["direct_execution"] = try_direct_execution(path)
    m["fact_host_refuses_to_execute"] = bool(m["direct_execution"].get("refused")) or \
        m["direct_execution"].get("shell_exit_status") not in (0,)
    if not m["fact_host_refuses_to_execute"]:
        problems.append("this host executed a foreign-ISA file, which contradicts "
                        "the whole premise of the fixture")

    # Declared/measured agreement on the remaining scalar declarations.
    d = fix["declared"]
    for key, got in (("elf_class", m["elf_class"]), ("elf_data", m["elf_data"]),
                     ("e_type", m["e_type"]), ("e_machine", m["e_machine"])):
        if key in d and d[key] != got:
            problems.append("declared %s=%r, measured %r" % (key, d[key], got))
    if "load_segments" in d and d["load_segments"] != m["load_segments"]:
        problems.append("declared load_segments=%r, measured %r"
                        % (d["load_segments"], m["load_segments"]))
    if d.get("matches_host_isa") is False and not m["fact_differs_from_host_isa"]:
        problems.append("declared not to match the host ISA, but it does")
    if d.get("directly_executable_here") is False and not m["fact_host_refuses_to_execute"]:
        problems.append("declared not directly executable here, but it ran")
    return m, problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/lexe-workloads-foreign")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    binroot = os.path.join(out, "bin")
    os.makedirs(binroot, exist_ok=True)

    t0 = time.time()
    asm, text, textsec = assemble(out)
    linkers = probe_linkers(out)

    records = []
    for fix in FIXTURES:
        rec = {k: fix[k] for k in ("id", "kind", "property", "notes")}
        rec["declared"] = fix["declared"]
        rec["assembly"] = {k: asm[k] for k in asm if k != "text_disassembly"}
        problems = []
        if not asm.get("compile_ok"):
            rec["verdict"] = {"status": "build-failed",
                              "problems": ["clang could not assemble the source",
                                           asm.get("diagnostics", "")[:400]]}
            records.append(rec)
            continue
        if not asm.get("relocation_free"):
            rec["verdict"] = {"status": "guardrail-failed", "problems": [
                "the object contains relocation sections %r: hand-linking it "
                "would mean resolving addresses by hand, which is a weaker claim "
                "than this corpus makes. Make every reference PC-relative again "
                "rather than relaxing this check."
                % (asm["relocation_sections"],)]}
            records.append(rec)
            continue
        if asm.get("independent_extraction_agrees") is False:
            rec["verdict"] = {"status": "guardrail-failed", "problems": [
                "an independent extraction of .text disagrees with this script's, "
                "so the provenance of the bytes cannot be defended"]}
            records.append(rec)
            continue

        if fix["kind"] == "object":
            path = os.path.join(binroot, fix["id"] + ".o")
            shutil.copyfile(asm["object"], path)
            rec["link"] = {"performed": False,
                           "note": "clang's object, copied unaltered"}
        else:
            blob, layout = link_exec(text, fix["e_type"], fix["base"])
            path = os.path.join(binroot, fix["id"])
            with open(path, "wb") as f:
                f.write(blob)
            rec["link"] = {
                "performed": True,
                "performed_by": "generate_foreign.py:link_exec",
                "reason": "no linker on this host accepts ELF machine 183",
                "bytes_written_by_the_linker_substitute":
                    "ELF header, one program header, .shstrtab and three section "
                    "headers. No instruction byte is produced or modified here.",
                **layout}
        os.chmod(path, 0o755)
        m, problems = verify(fix, path, asm)
        rec["measured"] = m
        rec["five_facts"] = {
            "1_compilation_succeeded": m.get("fact_compile_succeeded"),
            "2_output_is_a_valid_elf": m.get("fact_valid_elf"),
            "3_machine_type_is_aarch64": m.get("fact_machine_is_aarch64"),
            "4_structurally_executable": m.get("fact_structurally_executable"),
            "5_does_not_match_host_isa": m.get("fact_differs_from_host_isa"),
        }
        rec["verdict"] = {"status": "structural-ok" if not problems
                          else "structural-mismatch",
                          "problems": problems}
        rec["baseline_kind"] = "structural-only"
        rec["baseline_caveat"] = (
            "There is no direct-execution baseline for this fixture and there "
            "cannot be one on this host: no AArch64 kernel, no qemu-user, no "
            "cross libc. The only execution fact recorded is the measured "
            "refusal in measured.direct_execution. Do not read this fixture as "
            "AArch64 coverage.")
        records.append(rec)

    elapsed = round(time.time() - t0, 2)
    counts = {}
    for r in records:
        counts[r["verdict"]["status"]] = counts.get(r["verdict"]["status"], 0) + 1

    index = {
        "schema": "lexe.workload.foreign/1",
        "schema_notes": {
            "purpose": "valid ELF files for an ISA this host is not, so that a "
                       "consumer's architecture check can be reached at all",
            "proves": "that the fixture is a structurally executable AArch64 ELF",
            "does_not_prove": "anything about AArch64 support, anywhere",
            "baseline_kind": "structural-only: these fixtures cannot be executed "
                             "on this host, so they have no direct-execution "
                             "baseline and must not be cited as if they did",
            "verdict.status": "structural-ok means admitted; structural-mismatch "
                              "means the FIXTURE is wrong; guardrail-failed means "
                              "the provenance of the bytes could not be defended "
                              "and nothing was emitted",
        },
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generator": {"file": os.path.basename(__file__),
                      "sha256": sha256_file(os.path.abspath(__file__)),
                      "specs_dir": SPECS, "wall_seconds": elapsed},
        "host": host_facts(),
        "toolchain": {"assembler": "clang (integrated)",
                      "clang_version": tool_version("clang"),
                      "readelf_version": tool_version("readelf"),
                      "independent_extractor": asm.get("independent_extractor"),
                      "disassembler": asm.get("disassembler")},
        "link_route_probe": linkers,
        "blocked": [] if linkers["any_route_linked"] else [{
            "what": "an AArch64 executable produced by a real linker",
            "why": "no linker on this host accepts ELF machine 183",
            "evidence": [r["message"] for r in linkers["routes"]],
            "unblocked_by": "apt install gcc-aarch64-linux-gnu (or lld), which "
                            "needs authorisation this role does not have",
            "workaround_in_use": "generate_foreign.py links the file itself; see "
                                 "the module docstring for why that is a linker "
                                 "substitute and not a forgery",
        }],
        "assembly": asm,
        "counts": {"fixtures": len(records), **counts},
        "fixtures": records,
    }
    path = os.path.join(out, "index.json")
    with open(path, "w") as f:
        json.dump(index, f, indent=1, sort_keys=False)

    if not args.quiet:
        for r in records:
            print("%-22s %s" % (r["verdict"]["status"], r["id"]))
            for p in r["verdict"]["problems"]:
                print("                       ! %s" % p)
            if "five_facts" in r:
                print("                       facts: %s"
                      % ", ".join("%s=%s" % (k.split("_", 1)[1], v)
                                  for k, v in r["five_facts"].items()))
        print("\n%d fixtures, %s, %.2fs -> %s"
              % (len(records), ", ".join("%s=%d" % kv for kv in sorted(counts.items())),
                 elapsed, path))
    return 0 if counts.get("structural-ok", 0) == len(records) else 1


if __name__ == "__main__":
    sys.exit(main())

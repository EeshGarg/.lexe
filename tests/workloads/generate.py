#!/usr/bin/env python3
"""Linux ELF workload factory for .LEXE.

Builds a corpus of small, deterministic, intentionally unusual Linux programs,
records a DIRECT-EXECUTION baseline for each one, and emits a machine-readable
index. Nothing here knows anything about .LEXE: a specimen is accepted into the
corpus only because it was compiled, executed directly, and behaved as declared.

Usage (inside WSL):
    python3 generate.py [--out DIR] [--only SUBSTR] [--jobs N] [--skip-build]

Build products land in --out (default /tmp/lexe-workloads), never in the repo.
The corpus is a pure function of specs/ plus this file.
"""

import argparse
import concurrent.futures as futures
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SPECS = os.path.join(HERE, "specs")
REPO = os.path.dirname(os.path.dirname(HERE))

# The project's own namespaced private X server. No automated test may put a
# window on the developer's screen, and on WSLg that needs a private mount AND
# network namespace -- see the header of the script itself. The GUI specimens use
# it unchanged rather than starting an Xvfb of their own.
PD_LIB = os.path.join(REPO, "scripts", "lib", "private-display.sh")

COMMON_C = ["-std=gnu11", "-Wall", "-Wextra", "-D_GNU_SOURCE", "-I" + SPECS]
COMMON_CXX = ["-std=gnu++17", "-Wall", "-Wextra", "-I" + SPECS]

# -O3 is not "-O2 but more": it turns on automatic vectorisation and far more
# aggressive inlining and loop transformation, which is where hand-written
# integer code stops agreeing with itself if it had undefined behaviour in it,
# and where a fault the specimen depends on can be optimised out of existence.
# It is therefore a real axis and not a third spelling of the same build.
TOOLCHAINS = {
    "gcc-O0":   {"cc": "gcc",   "cxx": "g++",     "opt": ["-O0", "-g"]},
    "gcc-O2":   {"cc": "gcc",   "cxx": "g++",     "opt": ["-O2"]},
    "gcc-O3":   {"cc": "gcc",   "cxx": "g++",     "opt": ["-O3"]},
    "clang-O0": {"cc": "clang", "cxx": "clang++", "opt": ["-O0", "-g"]},
    "clang-O2": {"cc": "clang", "cxx": "clang++", "opt": ["-O2"]},
    "clang-O3": {"cc": "clang", "cxx": "clang++", "opt": ["-O3"]},
}


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


def fnv1a64(data):
    h = 0xCBF29CE484222325
    for byte in data:
        h ^= byte
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def tool_version(binary):
    r = sh([binary, "--version"])
    return (r.stdout or r.stderr).splitlines()[0].strip() if (r.stdout or r.stderr) else "unknown"


def host_facts():
    return {
        "uname": sh(["uname", "-srvmo"]).stdout.strip(),
        "distro": next((l.split("=", 1)[1].strip().strip('"')
                        for l in open("/etc/os-release") if l.startswith("PRETTY_NAME=")), "?"),
        "libc": (sh(["ldd", "--version"]).stdout.splitlines() or ["?"])[0].strip(),
        "nproc": int(sh(["nproc"]).stdout.strip() or 1),
        "page_size": os.sysconf("SC_PAGESIZE"),
        "kernel_unprivileged_userns": _read_first("/proc/sys/kernel/unprivileged_userns_clone"),
        "apparmor_userns_restrict": _read_first(
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
    }


def _read_first(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def elf_facts(path):
    """What the ELF actually is, read out of the file rather than assumed."""
    out = {}
    h = sh(["readelf", "-hdW", path])
    if h.returncode != 0:
        return {"readelf_failed": h.stderr.strip()[:200]}
    text = h.stdout
    m = re.search(r"^\s*Type:\s+(\S+)", text, re.M)
    out["e_type"] = m.group(1) if m else "?"
    m = re.search(r"^\s*Machine:\s+(.+)$", text, re.M)
    out["machine"] = m.group(1).strip() if m else "?"
    out["needed"] = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", text)
    rp = re.findall(r"\(RPATH\)\s+Library rpath: \[([^\]]+)\]", text)
    ru = re.findall(r"\(RUNPATH\)\s+Library runpath: \[([^\]]+)\]", text)
    out["rpath"] = rp[0] if rp else None
    out["runpath"] = ru[0] if ru else None
    out["has_dynamic_section"] = "Dynamic section at offset" in text
    flags_lines = re.findall(r"\(FLAGS\)\s+(.*)", text)
    out["bind_now"] = ("BIND_NOW" in text) or any("NOW" in x for x in flags_lines)
    p = sh(["readelf", "-lW", path])
    out["interpreter"] = None
    mi = re.search(r"\[Requesting program interpreter: ([^\]]+)\]", p.stdout)
    if mi:
        out["interpreter"] = mi.group(1)
    s = sh(["readelf", "-SW", path])
    out["has_symtab"] = ".symtab" in s.stdout
    out["has_debug_info"] = ".debug_info" in s.stdout
    f = sh(["file", "-b", path])
    out["file_says"] = f.stdout.strip()
    out["statically_linked"] = out["interpreter"] is None
    out["pie"] = out["e_type"] == "DYN"
    out["stripped"] = not out["has_symtab"]
    return out


# --------------------------------------------------------------------------
# The specimen table.
#
# Every field is a DECLARATION written before the specimen was ever run. The
# generator compiles each specimen, executes it directly, and compares the
# observation against these declarations; a disagreement is reported as a
# baseline mismatch, which means the FIXTURE is wrong, not the host.
#
#   expect      KEY -> exact value that must appear in the oracle stream
#   exit/signal the declared termination
#   elf         properties the built file must actually have (read with readelf)
#   files       staged into the run directory before the run
#   post        files the specimen must leave behind, checked after settle
# --------------------------------------------------------------------------

LIBS = [
    {"name": "libalpha.so", "src": ["libalpha.c"], "extra": []},
    {"name": "libbeta.so", "src": ["libbeta.c"], "extra": ["-L{LIBDIR}", "-lalpha", "-Wl,--enable-new-dtags",
                                                           "-Wl,-rpath,$ORIGIN"]},
    {"name": "libgamma.so", "src": ["libgamma.c"], "extra": ["-L{LIBDIR}", "-lbeta", "-Wl,--enable-new-dtags",
                                                             "-Wl,-rpath,$ORIGIN"]},
    {"name": "libplugin.so", "src": ["plugin.c"], "extra": []},
    {"name": "libver.so", "src": ["libver.c"],
     "extra": ["-Wl,--version-script=" + os.path.join(SPECS, "libver.map")]},
    # A C++ library, built with the C++ driver. Its whole reason to exist is that
    # an exception thrown inside it must be caught in the executable, which only
    # works if the two share one typeinfo, one vtable and one unwinder.
    {"name": "libthrower.so", "src": ["libthrower.cpp"], "lang": "c++", "extra": []},
]

SPECIMENS = []


def S(fid, src, family, prop, **kw):
    spec = {
        "id": fid,
        "family": family,
        "property": prop,
        "sources": src if isinstance(src, list) else [src],
        "toolchain": kw.get("tc", "gcc-O2"),
        "language": "c++" if str(src).endswith(".cpp") else "c",
        "cflags": list(kw.get("cflags", [])),
        "libs": list(kw.get("libs", [])),
        "stage": kw.get("stage", "plain"),
        "argv": list(kw.get("argv", [])),
        "env": dict(kw.get("env", {})),
        "stdin": kw.get("stdin", b""),
        # How the three standard streams are connected. See STDIO_SHAPES.
        "stdio": kw.get("stdio", "pipe"),
        "stdio_limit": kw.get("stdio_limit", 4096),
        "stdio_reference": kw.get("stdio_reference", False),
        # "private" = the project's namespaced X server; "none" = DISPLAY and
        # WAYLAND_DISPLAY removed outright; absent = inherited (console specimens
        # never look at it).
        "display": kw.get("display"),
        # Seconds to keep the private X server alive AFTER the launched process
        # has exited. Only meaningful with display="private".
        "display_hold_s": kw.get("display_hold_s", 0),
        # A path (relative to the run directory) whose APPEARANCE ends the hold.
        # Turns a fixed margin, which is a race, into a condition.
        "display_hold_until": kw.get("display_hold_until"),
        "declared": {
            "exit_code": kw.get("exit", 0),
            "signal": kw.get("signal"),
            "oracle_stream": kw.get("oracle", "stdout"),
            "expect": dict(kw.get("expect", {})),
            "post_files": dict(kw.get("post", {})),
            "duration_class": kw.get("duration", "sub-second"),
            "capabilities": list(kw.get("caps", [])),
            "filesystem_effects": list(kw.get("effects", [])),
            "process_behaviour": kw.get("procbeh", "single-process"),
            "elf": dict(kw.get("elf", {})),
            "bulk_check": kw.get("bulk"),
            # Facts about the CONNECTION rather than about the program, declared
            # before the shape is ever built. Checked in verdict_for.
            "stdio_expect": dict(kw.get("stdio_expect", {})),
            # None means "this must compile with NO diagnostics at all". A
            # string means a diagnostic is EXPECTED and must contain it. The
            # corpus compiling clean was previously an observation that happened
            # to hold; declaring it makes it a property the generator enforces.
            "build_warning_contains": kw.get("expect_build_warning"),
            "reaches_result_line": kw.get("signal") is None,
            "requires_result_pass": kw.get("result", True) and kw.get("signal") is None,
        },
        "staged_files": dict(kw.get("files", {})),
        "settle_s": kw.get("settle", 0.0),
        "runs": kw.get("runs", 1),
        "timeout_s": kw.get("timeout", 60.0),
        "notes": kw.get("notes", ""),
    }
    SPECIMENS.append(spec)
    return spec


DYN = {"e_type": "DYN", "statically_linked": False}
EXEC_NOPIE = {"e_type": "EXEC", "statically_linked": False}
SELF_OK = {"ARGC": "1", "PATTERN_HASH": None, "ARGV0_PRESENT": "yes"}

# ---- format and linkage --------------------------------------------------
S("linux-format-dynamic-pie", "self_report.c", "format", "dynamically linked PIE (the default)",
  elf=DYN, expect={"ARGC": "1", "ARGV0_PRESENT": "yes", "DOUBLE_MATH": "1.000000"},
  notes="The control case every other format variant is compared against.")
S("linux-format-dynamic-nonpie", "self_report.c", "format", "non-PIE (fixed load address)",
  cflags=["-no-pie", "-fno-pie"], elf=EXEC_NOPIE,
  expect={"ARGC": "1", "ARGV0_PRESENT": "yes"})
S("linux-format-static", "self_report.c", "format", "fully static, no interpreter",
  cflags=["-static"], elf={"statically_linked": True, "interpreter": None, "needed": []},
  expect={"ARGC": "1", "ARGV0_PRESENT": "yes"},
  notes="No ld.so, no NEEDED entries: nothing outside the file is consulted.")
S("linux-format-static-pie", "self_report.c", "format", "static PIE",
  cflags=["-static-pie", "-fPIE"], elf={"e_type": "DYN", "interpreter": None},
  expect={"ARGC": "1"})
S("linux-format-stripped", "self_report.c", "format", "stripped of its symbol table",
  cflags=["-s"], elf={"stripped": True, "has_symtab": False}, expect={"ARGC": "1"})
S("linux-format-unstripped-debug", "self_report.c", "format", "unstripped with DWARF",
  tc="gcc-O0", elf={"stripped": False, "has_symtab": True, "has_debug_info": True},
  expect={"ARGC": "1"})
S("linux-format-full-relro-now", "self_report.c", "format", "full RELRO and BIND_NOW",
  cflags=["-Wl,-z,relro", "-Wl,-z,now"], elf={"bind_now": True}, expect={"ARGC": "1"},
  notes="Eager binding: every dynamic relocation is resolved before main.")
S("linux-format-lazy-binding", "self_report.c", "format", "explicitly lazy binding",
  cflags=["-Wl,-z,lazy"], elf=DYN, expect={"ARGC": "1"},
  notes="Symbols resolve on first call through the PLT instead of at load.")
S("linux-format-large-binary", "big_data.c", "format", "a deliberately large executable",
  expect={"BIG_BYTES": "50331648", "BIG_FIRST": "yes", "BIG_LAST": "yes"},
  duration="sub-second", timeout=120.0,
  notes="48 MiB of initialised .data, checksummed at runtime so the pages must arrive.")
# `-static` was applied to exactly one program, self_report.c, which does almost
# nothing -- so the corpus declared static linking without ever exercising the
# parts of libc where static linking actually changes the answer. These three are
# those parts. The first two must produce EXACTLY the same oracle as their
# dynamic twins, which is the whole claim; the third must not, and says so.
S("linux-format-static-threads", "thread_modes.c", "format",
  "fully static AND threaded: the same answers as the dynamic build",
  cflags=["-static", "-pthread"], argv=["condvar"],
  elf={"statically_linked": True, "interpreter": None, "needed": []},
  procbeh="multi-threaded",
  expect={"THREAD_MODE": "condvar", "CONSUMER_STARTED": "yes",
          "ITEMS_PRODUCED": "64", "CONSUMED_SUM": "2080", "SUM_IS_2080": "yes"},
  notes="Static libpthread pulls in a different set of libc startup and "
        "cancellation paths than the shared one. Every deterministic line must "
        "match linux-thread-condvar-handoff exactly; if one does not, static "
        "linking changed behaviour and the corpus needs to know which line.")
S("linux-format-static-cxx-exceptions", "cxx_core.cpp", "format",
  "fully static C++: exceptions unwound by a statically linked libgcc",
  cflags=["-std=c++17", "-static"],
  elf={"statically_linked": True, "interpreter": None,
       "needed_excludes": ["libstdc++.so.6"]},
  expect={"CXX_STANDARD": "201703", "STATIC_INIT_ORDER": "12",
          "EXCEPTION_CAUGHT_BY_BASE_REF": "yes",
          "DESTRUCTOR_RAN_DURING_UNWIND": "yes",
          "TYPEID_MATCHES_DYNAMIC_TYPE": "yes",
          "DYNAMIC_CAST_DOWN_SUCCEEDS": "yes",
          "SORTED": "alpha,beta,gamma", "LAMBDA_RESULT": "133"},
  notes="Exception unwinding and RTTI through a statically linked libgcc and "
        "libstdc++ is the classic place a fully static C++ binary stops working "
        "-- the unwinder needs to find frame tables that are no longer where it "
        "looks for them. The twin is linux-cxx-core-cpp17.")
S("linux-format-static-resolver", "sock_resolve.c", "format",
  "fully static and calling getaddrinfo, which is the case glibc warns about",
  cflags=["-static"],
  elf={"statically_linked": True, "interpreter": None},
  expect_build_warning="statically linked applications requires at runtime",
  expect={"LOCALHOST_RC_IS_ZERO": "yes", "BOGUS_RC_IS_ZERO": "no",
          "ETC_HOSTS_READABLE": "yes", "SURVIVED_RESOLUTION": "yes"},
  caps=["/etc/hosts and the NSS configuration"],
  notes="THE specimen that is supposed to warn, and the reason the generator now "
        "treats compiler diagnostics as a declared property rather than a field "
        "nobody reads. glibc's name resolution loads NSS modules at runtime, so "
        "a static binary still needs shared libraries it does not list in "
        "NEEDED and no tool can see the dependency by reading the file. That is "
        "a legitimate and extremely common shape -- not a broken build -- and "
        "the link-time warning is the only place it is ever stated.")
S("linux-format-selfcontained", "embedded_blob.c", "format",
  "single self-contained executable with no external inputs",
  cflags=["-static"], elf={"statically_linked": True, "needed": []},
  expect={"BLOB_BYTES": "1048576", "NO_EXTERNAL_FILES": "yes"},
  caps=[], notes="Static, no files, no network, no environment dependence.")

# ---- shared libraries and dynamic loading --------------------------------
LIBCHAIN = {"ALPHA": "1000003", "BETA": "1000010", "GAMMA": "2000020",
            "CHAIN_CONSISTENT": "yes"}

S("linux-link-three-libs-ldpath", "uses_libs.c", "linkage",
  "three shared libraries found via LD_LIBRARY_PATH",
  cflags=["-L{LIBDIR}", "-lgamma", "-lbeta", "-lalpha"], stage="ldpath",
  elf={"needed_contains": ["libgamma.so", "libbeta.so", "libalpha.so"],
       "rpath": None, "runpath": None},
  expect=LIBCHAIN, caps=["shared-libraries-beside-the-binary"],
  notes="No RPATH at all: the binary is unrunnable without LD_LIBRARY_PATH.")
S("linux-link-rpath", "uses_libs.c", "linkage", "DT_RPATH (the old tag)",
  cflags=["-L{LIBDIR}", "-lgamma", "-lbeta", "-lalpha",
          "-Wl,--disable-new-dtags", "-Wl,-rpath,{STAGELIB}"],
  stage="rpath", elf={"rpath_set": True, "runpath": None}, expect=LIBCHAIN,
  notes="DT_RPATH cannot be overridden by LD_LIBRARY_PATH; DT_RUNPATH can.")
S("linux-link-runpath", "uses_libs.c", "linkage", "DT_RUNPATH (the new tag)",
  cflags=["-L{LIBDIR}", "-lgamma", "-lbeta", "-lalpha",
          "-Wl,--enable-new-dtags", "-Wl,-rpath,{STAGELIB}"],
  stage="runpath", elf={"runpath_set": True}, expect=LIBCHAIN)
S("linux-link-origin-relative", "uses_libs.c", "linkage",
  "relative library lookup through $ORIGIN",
  cflags=["-L{LIBDIR}", "-lgamma", "-lbeta", "-lalpha",
          "-Wl,--enable-new-dtags", "-Wl,-rpath,$ORIGIN/../lib"],
  stage="origin", elf={"runpath": "$ORIGIN/../lib"}, expect=LIBCHAIN,
  caps=["relocatable-directory-tree"],
  notes="The whole bin/ + lib/ tree can be moved anywhere and still runs.")
S("linux-link-symbol-versioning", "symver_user.c", "linkage",
  "a versioned symbol resolving to the default version",
  cflags=["-L{LIBDIR}", "-lver", "-Wl,-rpath,{LIBDIR}"], stage="ldpath",
  elf={"needed_contains": ["libver.so"]},
  expect={"VER_VALUE": "22", "RESOLVED_TO_DEFAULT_V2": "yes"})
S("linux-dlopen-plugin", "dlopen_user.c", "linkage", "dlopen of a library built alongside it",
  argv=["{LIBDIR}/libplugin.so", "ok"], stage="dlopen",
  expect={"DLOPEN": "ok", "DLSYM_PROBE": "yes", "PROBE_14": "43",
          "PLUGIN_NAME": "lexe-workload-plugin", "OUTCOME_AS_DECLARED": "yes"},
  caps=["dlopen-at-runtime"])
S("linux-dlopen-missing", "dlopen_user.c", "linkage",
  "dlopen of a library that is not there, handled rather than fatal",
  argv=["{LIBDIR}/libnotpresent.so", "fail"], stage="dlopen",
  expect={"DLOPEN": "fail", "OUTCOME_AS_DECLARED": "yes"},
  notes="Same binary as linux-dlopen-plugin; only the argument differs.")
# The three specimens above bake an ABSOLUTE path into the binary -- {STAGELIB}
# for the two rpath/runpath entries, {LIBDIR} for symbol versioning -- so the
# file is not relocatable and cannot start anywhere but the directory it was
# built in. That is a legitimate shape and worth keeping: it is how a great deal
# of locally built software links. But it also HIDES the property those
# specimens exist to test, because a binary that never reaches main covers
# nothing, and symbol versioning in particular was therefore untested by the
# corpus rather than merely untested by accident.
#
# So each gets a $ORIGIN-relative twin below. The absolute ones stay. This is an
# added case, not a replaced one, and the pair is more informative than either
# alone: the difference between the twins is exactly one link-line argument.
S("linux-link-rpath-origin", "uses_libs.c", "linkage",
  "DT_RPATH (the old tag) with a relocatable $ORIGIN value",
  cflags=["-L{LIBDIR}", "-lgamma", "-lbeta", "-lalpha",
          "-Wl,--disable-new-dtags", "-Wl,-rpath,$ORIGIN/../lib"],
  stage="origin", elf={"rpath": "$ORIGIN/../lib", "runpath": None},
  expect=LIBCHAIN, caps=["relocatable-directory-tree"],
  notes="The twin of linux-link-rpath. Two independent properties meet here and "
        "nowhere else in the corpus: DT_RPATH cannot be overridden by "
        "LD_LIBRARY_PATH, and $ORIGIN survives the tree being moved.")
S("linux-link-symbol-versioning-origin", "symver_user.c", "linkage",
  "a versioned symbol resolved through a relocatable $ORIGIN path",
  cflags=["-L{LIBDIR}", "-lver", "-Wl,--enable-new-dtags",
          "-Wl,-rpath,$ORIGIN/../lib"],
  stage="origin",
  elf={"runpath": "$ORIGIN/../lib", "needed_contains": ["libver.so"]},
  expect={"VER_VALUE": "22", "RESOLVED_TO_DEFAULT_V2": "yes"},
  caps=["relocatable-directory-tree"],
  notes="The twin of linux-link-symbol-versioning, whose DT_RUNPATH is the "
        "absolute build-tree lib directory. Symbol versioning is the property "
        "under test, and it cannot be tested by a binary that never starts.")
S("linux-dlopen-plugin-origin", "dlopen_user.c", "linkage",
  "dlopen of a bare soname resolved through the caller's own $ORIGIN RUNPATH",
  cflags=["-Wl,--enable-new-dtags", "-Wl,-rpath,$ORIGIN/../lib"],
  argv=["libplugin.so", "ok"], stage="origin",
  elf={"runpath": "$ORIGIN/../lib"},
  expect={"DLOPEN": "ok", "DLSYM_PROBE": "yes", "PROBE_14": "43",
          "PLUGIN_NAME": "lexe-workload-plugin", "OUTCOME_AS_DECLARED": "yes"},
  caps=["dlopen-at-runtime", "relocatable-directory-tree"],
  notes="The twin of linux-dlopen-plugin, which names the library by an absolute "
        "build-tree path in argv. Here the argument is a bare soname and glibc "
        "resolves it through the RUNPATH of the object that called dlopen, so "
        "the whole tree moves and the dlopen still succeeds. Note the stage: "
        "unlike the dlopen stage this one sets no LD_LIBRARY_PATH, so $ORIGIN "
        "is the only thing that can be finding the library.")
S("linux-cxx-shared-runtime", "cxx_runtime.cpp", "linkage",
  "C++ program against the shared C++ runtime",
  elf={"needed_contains": ["libstdc++.so.6"]},
  expect={"STATIC_INIT_ORDER": "12", "EXCEPTION_CAUGHT": "by-base-ref",
          "EXCEPTION_WHAT": "deliberate", "THREADS_JOINED": "4", "THREAD_TOTAL": "1919605",
          "SORTED": "alpha,beta,gamma"},
  caps=["libstdc++"], procbeh="multi-threaded",
  notes="Static constructors, an unwound exception, std::thread and iostreams.")
S("linux-cxx-static-runtime", "cxx_runtime.cpp", "linkage",
  "the same C++ program with the C++ runtime linked in",
  cflags=["-static-libstdc++", "-static-libgcc"],
  elf={"needed_excludes": ["libstdc++.so.6"]},
  expect={"STATIC_INIT_ORDER": "12", "EXCEPTION_CAUGHT": "by-base-ref",
          "THREADS_JOINED": "4"},
  procbeh="multi-threaded",
  notes="Exception unwinding through a statically linked libgcc is the risk here.")

# ---- process behaviour ---------------------------------------------------
S("linux-proc-threads-4", "proc_threads.c", "process", "four threads, joined",
  cflags=["-pthread"], argv=["4"], procbeh="multi-threaded",
  expect={"THREADS_REQUESTED": "4", "THREADS_STARTED": "4", "TOTAL": "3839146",
          "ALL_THREADS_STARTED": "yes"})
S("linux-proc-threads-256", "proc_threads.c", "process", "many threads (256)",
  cflags=["-pthread"], argv=["256"], procbeh="multi-threaded",
  expect={"THREADS_REQUESTED": "256", "THREADS_STARTED": "256", "TOTAL": "245759289",
          "ALL_THREADS_STARTED": "yes"},
  caps=["256-concurrent-threads"])
S("linux-proc-fork-wait", "proc_fork_wait.c", "process", "fork and reap a child",
  procbeh="forks-one-child",
  expect={"FORK_OK": "yes", "REAPED": "yes", "EXITED_NORMALLY": "yes", "CHILD_EXIT": "17"})
S("linux-proc-exec-self", "proc_exec_self.c", "process", "execve of its own image",
  expect={"PHASE": "two", "ARGC": "2"}, procbeh="replaces-own-image",
  notes="Two incarnations, one process. PHASE=one then PHASE=two on one stream.")
S("linux-proc-exec-helper", "proc_exec_helper.c", "process",
  "execve of a second binary shipped beside it", stage="helper", argv=["{HELPER}"],
  procbeh="replaces-own-image", result=False,
  expect={"PHASE": "pre-exec", "CHILD_ROLE": "exec-target", "CHILD_EXIT_INTENT": "0"},
  notes="After the exec this process IS helper_child, which prints no RESULT line "
        "of its own: the declared end state is the helper output plus exit 0.")
S("linux-proc-fork-exec", "proc_fork_exec.c", "process", "fork then exec in the child",
  stage="helper", argv=["{HELPER}"], procbeh="forks-and-execs",
  expect={"FORK_OK": "yes", "CHILD_ROLE": "forked", "CHILD_EXIT": "23",
          "EXEC_IN_CHILD_OK": "yes"})
S("linux-proc-grandchild", "proc_grandchild.c", "process", "three generations of processes",
  procbeh="child-and-grandchild",
  effects=["creates gen1.marker, gen2.marker, gen3.marker in the working directory"],
  expect={"CHILD_EXIT": "13", "GEN1_MARKER": "yes", "GEN2_MARKER": "yes", "GEN3_MARKER": "yes"})
S("linux-proc-daemon-double-fork", "proc_daemon.c", "process",
  "double fork with setsid, parent exits immediately",
  procbeh="daemonises", settle=1.0,
  expect={"STAGE": "parent", "PARENT_EXIT": "0", "FORK_OK": "yes"},
  post={"daemon.log": ["DAEMON_STARTED=yes", "DAEMON_SID_CHANGED=yes",
                      "DAEMON_IS_SESSION_LEADER=no", "DAEMON_RESULT=PASS"]},
  effects=["the daemon writes daemon.log after the launching process has exited"],
  notes="The launcher sees exit 0 while work continues in a detached session. The daemon is deliberately NOT the session leader: that is what the second fork buys, and the first version of this entry declared it backwards.")
S("linux-proc-orphan", "proc_orphan.c", "process",
  "a parent that exits leaving a live child behind",
  procbeh="leaves-orphan", settle=1.5,
  expect={"FORK_OK": "yes", "CHILD_LEFT_RUNNING": "yes", "PARENT_EXITS_FIRST": "yes"},
  post={"orphan.log": ["CHILD_SURVIVED_PARENT=yes", "ORPHAN_RESULT=PASS"]},
  effects=["orphan.log appears ~400ms after the main process has exited"])
S("linux-proc-wait-signal-status", "proc_signal_death.c", "process",
  "a child killed by a signal, status reported by the parent",
  procbeh="forks-one-child",
  expect={"SIGNALLED": "yes", "TERM_SIGNAL": "9", "TERM_SIGNAL_IS_KILL": "yes"})
S("linux-proc-posix-spawn", "proc_posix_spawn.c", "process",
  "posix_spawn instead of fork plus exec", stage="helper", argv=["{HELPER}"],
  procbeh="spawns-child",
  expect={"SPAWN_RC": "0", "SPAWN_OK": "yes", "CHILD_ROLE": "spawned", "CHILD_EXIT": "31"})
S("linux-proc-session", "proc_session.c", "process",
  "process group and session relationships", procbeh="forks-one-child",
  expect={"CHILD_SETSID_OK": "yes"})

# ---- signals -------------------------------------------------------------
S("linux-signal-catch-report", "sig_catch.c", "signals",
  "a handler that catches two signals and reports what it saw",
  expect={"SIGACTION_USR1": "yes", "SIGACTION_USR2": "yes", "USR1_COUNT": "2",
          "USR2_COUNT": "1", "SI_CODE_IS_TKILL_OR_USER": "yes",
          "SURVIVED_CAUGHT_SIGNALS": "yes"})
S("linux-signal-ignored", "sig_ignore.c", "signals", "a signal that is ignored",
  expect={"IGNORE_SIGTERM": "yes", "STILL_RUNNING_AFTER_SIGTERM": "yes",
          "STILL_RUNNING_AFTER_SIGINT": "yes"},
  notes="SIGTERM three times and it keeps going: polite shutdown does not work here.")
S("linux-signal-death-sigterm", "sig_die.c", "signals", "dies from SIGTERM by default",
  argv=["term"], signal="SIGTERM", exit=None,
  expect={"SIGNAL_SELECTED": "term", "EXPECT_DEATH": "sigterm-default"})
S("linux-signal-death-sigquit", "sig_die.c", "signals", "dies from SIGQUIT (core disposition)",
  argv=["quit"], signal="SIGQUIT", exit=None,
  expect={"SIGNAL_SELECTED": "quit", "EXPECT_DEATH": "sigquit-default"})
S("linux-outcome-sigsegv", "sig_segv.c", "outcome", "crashes with SIGSEGV",
  signal="SIGSEGV", exit=None,
  expect={"FAULT_KIND": "null-write", "EXPECT_DEATH": "sigsegv"},
  notes="A genuine fault, not a raise(): a write through a volatile null pointer.")
S("linux-outcome-abort", "sig_abort.c", "outcome", "aborts with SIGABRT after writing stderr",
  signal="SIGABRT", exit=None,
  expect={"ABORT_REASON": "deliberate-invariant-violation", "EXPECT_DEATH": "sigabrt"})
S("linux-signal-alarm-bounded", "sig_alarm.c", "signals",
  "a bounded run ended by SIGALRM in pause()", duration="second", timeout=30.0,
  expect={"SIGACTION_ALRM": "yes", "ALARM_FIRED": "yes", "ALARM_DELIVERED": "yes"})
S("linux-signal-sigpipe-default", "sig_pipe.c", "signals",
  "dies from SIGPIPE writing to a closed pipe", argv=["default"],
  signal="SIGPIPE", exit=None, expect={"MODE": "default", "PIPE_CREATED": "yes"})
S("linux-signal-sigpipe-ignored", "sig_pipe.c", "signals",
  "sees EPIPE instead, because SIGPIPE is ignored", argv=["ignore"],
  expect={"MODE": "ignore", "WRITE_RETURN": "-1", "WRITE_ERRNO": "EPIPE",
          "EPIPE_OBSERVED": "yes"})
S("linux-signal-sigchld-reaper", "sig_chld.c", "signals",
  "reaping five children from inside a SIGCHLD handler", procbeh="forks-five-children",
  expect={"SIGACTION_CHLD": "yes", "CHILDREN_FORKED": "5",
          "CHILDREN_REAPED_IN_HANDLER": "5", "ALL_REAPED": "yes"})

# ---- I/O -----------------------------------------------------------------
STDIN_4K = bytes(((i * 37 + 11) & 0xFF) for i in range(4096))

S("linux-io-stdin-consumed", "io_stdin.c", "io", "consumes stdin to EOF",
  stdin=STDIN_4K, expect={"STDIN_BYTES": "4096", "READ_TO_EOF": "yes",
                          "STDIN_NOT_EMPTY": "yes"},
  caps=["stdin-must-be-connected-and-closable"],
  notes="A launcher that leaves stdin open forever makes this hang, not fail.")
S("linux-io-stdout-only", "io_stdout.c", "io", "writes stdout and nothing else",
  expect={"STDERR_BYTES_WRITTEN": "0"})
S("linux-io-stderr-only", "io_stderr.c", "io", "writes stderr and nothing else",
  oracle="stderr", expect={"STDOUT_BYTES_WRITTEN": "0"},
  notes="The oracle itself is on fd 2; stdout must be empty.")
S("linux-io-both-streams", "io_both.c", "io", "writes both streams",
  expect={"OUT_TOTAL": "8"},
  notes="Deterministic within each stream; the merged order is not a contract.")
S("linux-io-pipe-roundtrip", "io_pipe.c", "io", "two pipes, request and response",
  procbeh="forks-one-child",
  expect={"PIPES_CREATED": "yes", "WROTE_ALL": "yes", "READ_REPLY": "yes",
          "HASH_MATCHES": "yes", "CHILD_EXIT": "0"})
S("linux-io-fifo", "io_fifo.c", "io", "a named FIFO in the working directory",
  procbeh="forks-one-child", effects=["creates and removes wl.fifo"],
  expect={"MKFIFO": "yes", "FIFO_OPEN_READ": "yes", "FIFO_BYTES": "23",
          "FIFO_PAYLOAD": "FIFO-PAYLOAD-0123456789", "FIFO_PAYLOAD_OK": "yes",
          "WRITER_EXIT": "0"},
  caps=["mkfifo-in-the-working-directory"])
S("linux-io-many-fds", "io_fd_many.c", "io", "256 file descriptors open at once",
  expect={"FDS_REQUESTED": "256", "FDS_OPENED": "256", "STOP_ERRNO": "NONE",
          "REACHED_256": "yes"},
  caps=["at-least-260-file-descriptors"],
  effects=["creates and removes 256 files named fd_NNN.tmp"])
S("linux-io-bulk-stdout", "io_bulk_stdout.c", "io", "8 MiB on stdout",
  oracle="stderr", bulk={"stream": "stdout", "bytes_key": "BULK_BYTES",
                         "fnv_key": "BULK_FNV1A"},
  expect={"BULK_BYTES": "8388608"}, timeout=120.0,
  notes="The runner recomputes FNV-1a over the captured stream and compares.")
S("linux-io-binary-stdout", "io_binary_stdout.c", "io",
  "all 256 byte values on stdout, including NUL", oracle="stderr",
  bulk={"stream": "stdout", "bytes_key": "BINARY_BYTES", "fnv_key": "BINARY_FNV1A"},
  expect={"BINARY_BYTES": "256"},
  notes="Anything that treats stdout as text will corrupt this.")
# ---- output volume and concurrency ---------------------------------------
# One property each, and all of them about the SIZE and the TIMING of output
# rather than its content. linux-io-bulk-stdout above covers 8 MiB; these cover
# what 8 MiB does not: hundreds of megabytes, two bulk streams at once, bulk
# followed by a non-zero exit, output that arrives slowly, and bulk binary.
#
# Every one of them attests to what it wrote with a SHA-256 it computes itself
# (specs/orc_bulk.h), and the runner recomputes that digest over the stream it
# captured. A byte count alone cannot tell a truncated stream from a reordered
# one, or from one whose NUL bytes were eaten.
#
# The sizes were chosen to make the property observable and for no other reason:
# 4 MiB is smaller than any plausible buffer, 64 MiB is larger than any, and
# 256 MiB is large enough that holding the whole stream in memory has to be a
# decision somebody made on purpose. None of them is tuned to what anything can
# currently cope with.
S("linux-io-stream-4mib", "io_stream.c", "io",
  "4 MiB on stdout with both digests attested", argv=["4"], oracle="stderr",
  bulk={"stream": "stdout", "bytes_key": "STREAM_BYTES",
        "sha_key": "STREAM_SHA256", "fnv_key": "STREAM_FNV1A"},
  expect={"STREAM_REQUESTED_BYTES": "4194304", "STREAM_BYTES": "4194304",
          "STREAM_COMPLETE": "yes", "EXIT_CODE": "0"}, timeout=120.0,
  notes="The small end of the parameterised family, and the only one where both "
        "digests are verified: FNV-1a has to be recomputed a byte at a time in "
        "Python, which is seconds at 8 MiB and minutes at 256 MiB.")
S("linux-io-stream-64mib", "io_stream.c", "io", "64 MiB on stdout",
  argv=["64"], oracle="stderr",
  bulk={"stream": "stdout", "bytes_key": "STREAM_BYTES", "sha_key": "STREAM_SHA256"},
  expect={"STREAM_BYTES": "67108864", "STREAM_COMPLETE": "yes"}, timeout=300.0,
  caps=["a consumer that does not hold the whole stream in memory"],
  notes="The same source and the same stream as the 4 MiB entry, and 4 MiB is a "
        "byte-for-byte prefix of this one -- verified directly -- which is what "
        "makes the family a size experiment rather than unrelated blobs.")
S("linux-io-stream-256mib", "io_stream.c", "io", "256 MiB on stdout",
  argv=["256"], oracle="stderr", duration="seconds",
  bulk={"stream": "stdout", "bytes_key": "STREAM_BYTES", "sha_key": "STREAM_SHA256"},
  expect={"STREAM_BYTES": "268435456", "STREAM_COMPLETE": "yes"}, timeout=600.0,
  caps=["a consumer that does not hold the whole stream in memory"],
  notes="Measured directly: 2.55 s wall and a peak RSS of 1536 kB for the "
        "specimen itself. The memory cost of 256 MiB of output belongs entirely "
        "to whatever is reading it, which is the point of having this size.")
S("linux-io-stream-both-128mib", "io_stream_both.c", "io",
  "128 MiB on stdout and 128 MiB on stderr, interleaved 64 KiB at a time",
  argv=["128"], oracle="stderr", duration="seconds",
  bulk={"stream": "stdout", "bytes_key": "OUT_BYTES", "sha_key": "OUT_SHA256",
        "also": [{"stream": "stderr", "delimiter_key": "ERR_PAYLOAD_DELIMITER",
                  "bytes_key": "ERR_PAYLOAD_BYTES",
                  "sha_key": "ERR_PAYLOAD_SHA256"}]},
  expect={"OUT_BYTES": "134217728", "ERR_PAYLOAD_BYTES": "134217728",
          "ERR_PAYLOAD_DELIMITER": "<<<LEXE-BULK-STDERR-PAYLOAD>>>",
          "BOTH_STREAMS_COMPLETE": "yes"}, timeout=600.0,
  caps=["both streams read concurrently"],
  notes="The deadlock shape, and measured directly: a reader that drains stdout "
        "to EOF before touching stderr stops after exactly 65536 bytes -- one "
        "pipe buffer -- and never resumes, because the specimen is then blocked "
        "writing to stderr and will never close stdout. A polling reader takes "
        "1.9 s for all 256 MiB. Both streams are bulk, so the oracle is appended "
        "to stderr after the payload, which is FRAMED by a delimiter line rather "
        "than located by a byte offset: the offset counted the FIXTURE_ID header, "
        "whose length comes from the environment, so a value declared "
        "deterministic moved from 129 to 122 the moment the environment was "
        "cleared. The absolute offset is still reported, as an observation.")
S("linux-io-stream-fail-64mib", "io_stream.c", "io",
  "64 MiB on stdout and then a non-zero exit", argv=["64", "3"],
  oracle="stderr", exit=3,
  bulk={"stream": "stdout", "bytes_key": "STREAM_BYTES", "sha_key": "STREAM_SHA256"},
  expect={"STREAM_BYTES": "67108864", "STREAM_COMPLETE": "yes",
          "STREAM_DECLARED_EXIT": "3", "EXIT_CODE": "3"}, timeout=300.0,
  notes="Bulk output and a failing exit status are independent facts. Anything "
        "that abandons the stream once the status is non-zero loses 64 MiB the "
        "program successfully wrote and reported the digest of.")
S("linux-io-stream-slow-paced", "io_stream_slow.c", "io",
  "output that arrives slowly, in bursts, with a silent tail",
  argv=["16", "150", "1000"], oracle="stderr", duration="seconds",
  bulk={"stream": "stdout", "bytes_key": "SLOW_BYTES", "sha_key": "SLOW_SHA256"},
  expect={"SLOW_TICKS_REQUESTED": "16", "SLOW_TICKS_WRITTEN": "16",
          "SLOW_GAP_MS": "150", "SLOW_TAIL_MS": "1000",
          "SLOW_BYTES": "524288", "SLOW_TAIL_ELAPSED": "yes"}, timeout=120.0,
  notes="Sixteen 32 KiB bursts 150 ms apart, then a full second of silence with "
        "both streams still open. Measured directly at 3.26 s wall with bursts "
        "landing at 0, 151, 301 ... 2257 ms. Each burst begins with an ASCII "
        "TICK-nnnn marker, so which burst was lost is visible in the stream "
        "itself rather than only in the total.")
S("linux-io-binary-bulk-16mib", "io_binary_bulk.c", "io",
  "16 MiB of binary on stdout: every byte value, NULs, CRLF, 0x1A, bad UTF-8",
  argv=["16"], oracle="stderr",
  bulk={"stream": "stdout", "bytes_key": "BINARY_BYTES", "sha_key": "BINARY_SHA256"},
  expect={"BINARY_BYTES": "16777216", "BINARY_VALUES_SEEN": "256",
          "BINARY_ALL_256_VALUES": "yes", "BINARY_HAS_NUL": "yes",
          "BINARY_ALL_HAZARDS_PLACED": "yes", "BINARY_NUL_COUNT": None,
          "BINARY_HAZARD_OFFSETS":
              "crlf@1024,cr@4096,nul@65534,doseof@1048576,badutf8@1048640"},
  timeout=300.0,
  notes="linux-io-binary-stdout covers all 256 values in 256 bytes. At volume "
        "the failures are different ones: newline translation, stopping at a "
        "NUL, decoding to text and re-encoding, treating 0x1A as end of file. "
        "The eight-NUL run at offset 65534 deliberately straddles a 64 KiB "
        "boundary. Measured directly: 256 distinct values present, 65866 NULs.")
S("linux-io-tty-detect", "io_tty.c", "io", "reports whether its fds are terminals",
  expect={"STDIN_ISATTY": "no", "STDOUT_ISATTY": "no", "STDERR_ISATTY": "no",
          "ALL_FDS_OPEN": "yes"},
  notes="Declared for a pipe-captured run; on a real tty the answers change.")
S("linux-io-dup2-redirect", "io_dup2.c", "io", "rewires its own stdout mid-run",
  effects=["creates redirected.txt"],
  expect={"DUP_SAVED": "yes", "DUP2_OK": "yes", "RESTORE_OK": "yes",
          "FILE_BYTES": "20", "FILE_CONTENT_OK": "yes", "STDOUT_RESTORED": "yes"})

# ---- stdio shapes --------------------------------------------------------
#
# A launcher once discarded the program's output entirely, so the CONNECTION got
# its own family. Two groups live here.
#
# The first is a matrix: io_stdio_shape.c, compiled once, launched through all
# eight shapes in STDIO_SHAPES. It varies nothing itself and reports what its
# three fds actually ARE -- fifo, regular file, character device or closed;
# seekable or not; writable or EBADF -- so each shape has a different
# deterministic answer and the difference between them is the measurement. A pipe
# and /dev/null both give STDIN_BYTES=0, which is why byte counts alone cannot
# tell the shapes apart and STDIN_KIND exists.
#
# The second group pushes specimens that already exist through the shapes that
# TRANSFORM a stream, because that is where output is actually lost:
#   - `tee` must be byte-exact, including NUL bytes;
#   - a command substitution strips trailing newlines and silently drops NULs;
#   - a consumer that closes early truncates, and whether the writer even NOTICES
#     depends entirely on whether the stream was bigger than one pipe buffer.
# That last pair is the most useful thing in this family: 4158 bytes fit in a
# pipe buffer, so the writer reports complete success while the consumer keeps
# 1024 bytes and nothing anywhere returns an error. 4 MiB does not fit, so the
# same shape kills the writer with SIGPIPE. Same shape, opposite symptoms, and a
# consumer that tested only one size would conclude the wrong thing about both.

SHAPE_PAYLOAD = {"stream": "stdout", "bytes_key": "STDOUT_CLAIMED_BYTES",
                 "sha_key": "STDOUT_CLAIMED_SHA256"}
SHAPE_OK = {"WRITE_STDOUT": "ok", "SELF_CONSISTENT": "yes",
            "STDOUT_PAYLOAD_DELIMITER": "<<<LEXE-STDIO-SHAPE-PAYLOAD>>>",
            "STDOUT_CLAIMED_BYTES": "4158"}

S("linux-stdio-shape-pipe", "io_stdio_shape.c", "stdio",
  "all three streams are pipes: the control shape", oracle="stderr",
  bulk=SHAPE_PAYLOAD,
  expect=dict(SHAPE_OK, STDIN_KIND="fifo", STDOUT_KIND="fifo", STDERR_KIND="fifo",
              STDIN_ISATTY="no", STDOUT_ISATTY="no", STDERR_ISATTY="no",
              STDIN_SEEKABLE="no", STDOUT_SEEKABLE="no", STDOUT_OPEN="yes",
              STDOUT_APPEND="no", STDIN_BYTES="0", READ_STDIN="ok",
              STDIN_AT_EOF="yes"),
  notes="Every other shape in this family is compared against this one. The "
        "specimen is identical in all eight; only the connection differs.")
S("linux-stdio-shape-file", "io_stdio_shape.c", "stdio",
  "stdout and stderr are regular files", oracle="stderr", stdio="file",
  bulk=SHAPE_PAYLOAD,
  expect=dict(SHAPE_OK, STDIN_KIND="fifo", STDOUT_KIND="regular",
              STDERR_KIND="regular", STDOUT_SEEKABLE="yes", STDOUT_ISATTY="no",
              STDOUT_OPEN="yes", STDOUT_APPEND="no", STDIN_BYTES="0"),
  notes="A regular file is seekable and glibc fully buffers it, so `prog >out` "
        "is not merely a pipe pointed somewhere else. The runner reads the file "
        "back and recomputes the digest the specimen attested to.")
S("linux-stdio-shape-tee", "io_stdio_shape.c", "stdio",
  "stdout through tee: two copies of one stream, which must be identical",
  oracle="stderr", stdio="tee", stdio_reference=True, bulk=SHAPE_PAYLOAD,
  stdio_expect={"tee_copy_matches_captured": True, "captured_equals_reference": True},
  expect=dict(SHAPE_OK, STDOUT_KIND="fifo", STDIN_KIND="fifo", STDERR_KIND="fifo"),
  notes="tee is declared LOSSLESS here and verified twice: its file copy against "
        "the copy that reached the runner, and both against a reference capture "
        "of the same program through a plain pipe.")
S("linux-stdio-shape-cmdsub", "io_stdio_shape.c", "stdio",
  "stdout captured by a shell command substitution, which strips trailing newlines",
  oracle="stderr", stdio="cmdsub", stdio_reference=True,
  stdio_expect={"captured_equals_reference": False,
                "captured_equals_reference_rstrip_newlines": True,
                "trailing_newlines_lost": 1},
  expect=dict(SHAPE_OK, STDOUT_KIND="fifo"),
  notes="`out=$(prog)` is how an enormous amount of real scripting invokes a "
        "program, and it is LOSSY BY DESIGN. There is no bulk digest check here "
        "because the specimen's attested SHA-256 is of what it WROTE and the "
        "shape altered it; the loss is declared as an exact relation to the "
        "reference capture instead, so it is measured rather than assumed.")
S("linux-stdio-shape-earlyclose", "io_stdio_shape.c", "stdio",
  "a consumer that closes after 1024 bytes, on a stream small enough to fit one "
  "pipe buffer", oracle="stderr", stdio="earlyclose", stdio_limit=1024,
  stdio_reference=True,
  stdio_expect={"consumer_reached_limit": True, "consumer_closed_after_bytes": 1024,
                "captured_is_prefix_of_reference": True},
  expect=dict(SHAPE_OK, STDOUT_KIND="fifo", STDERR_KIND="regular"),
  notes="THE quiet case. All 4158 bytes fit in the 64 KiB pipe buffer, so every "
        "write succeeds, WRITE_STDOUT=ok, RESULT=PASS and the exit code is 0 -- "
        "while the consumer kept 1024 bytes and threw the rest away. Nothing "
        "anywhere returns an error. Compare linux-stdio-earlyclose-4mib, the "
        "same shape over a stream that does not fit, where the writer dies.")
S("linux-stdio-shape-devnull-stdin", "io_stdio_shape.c", "stdio",
  "stdin is /dev/null: a character device at EOF, not a pipe",
  oracle="stderr", stdio="devnull-stdin", bulk=SHAPE_PAYLOAD,
  expect=dict(SHAPE_OK, STDIN_KIND="chardev", STDIN_BYTES="0", READ_STDIN="ok",
              STDIN_AT_EOF="yes", STDIN_ISATTY="no", STDIN_SEEKABLE="yes",
              STDOUT_KIND="fifo"),
  notes="The byte count is 0, exactly as it is for an empty pipe. STDIN_KIND is "
        "the only thing that separates them, and the difference matters: a "
        "launcher that 'connects stdin' by handing over a pipe it never closes "
        "makes a program that reads to EOF hang rather than fail.")
S("linux-stdio-shape-file-stdin", "io_stdio_shape.c", "stdio",
  "stdin is a regular file: seekable, with real content",
  oracle="stderr", stdio="file-stdin", stdin=STDIN_4K, bulk=SHAPE_PAYLOAD,
  expect=dict(SHAPE_OK, STDIN_KIND="regular", STDIN_SEEKABLE="yes",
              STDIN_BYTES="4096", READ_STDIN="ok", STDIN_AT_EOF="yes",
              STDOUT_KIND="fifo"),
  notes="`prog <in.dat`. The same 4096 bytes linux-io-stdin-consumed is fed "
        "through a pipe, arriving through a seekable fd instead.")
S("linux-stdio-shape-closed-stdout", "io_stdio_shape.c", "stdio",
  "fd 1 is closed outright, so writing to it fails with EBADF",
  oracle="stderr", stdio="closed-stdout",
  expect={"STDOUT_KIND": "closed", "STDOUT_OPEN": "no", "STDOUT_SEEKABLE": "no",
          "STDOUT_ISATTY": "no", "WRITE_STDOUT": "EBADF", "SELF_CONSISTENT": "yes",
          "STDERR_KIND": "fifo", "STDIN_BYTES": "0"},
  notes="`prog >&-`, which a careless supervisor produces by closing a handle it "
        "meant to redirect. The specimen survives it and says so; a program that "
        "assumed fd 1 was open would write its output into whatever opened next.")

# ---- the transforming shapes over streams that already exist -------------
S("linux-stdio-file-4mib", "io_stream.c", "stdio",
  "4 MiB to a regular file rather than a pipe", argv=["4"], oracle="stderr",
  stdio="file",
  bulk={"stream": "stdout", "bytes_key": "STREAM_BYTES", "sha_key": "STREAM_SHA256"},
  expect={"STREAM_BYTES": "4194304", "STREAM_COMPLETE": "yes"}, timeout=120.0,
  notes="The same stream as linux-io-stream-4mib into a seekable destination, "
        "where nothing throttles the writer and there is no 64 KiB buffer to "
        "block on. The digest must be identical to the pipe capture's.")
S("linux-stdio-tee-4mib", "io_stream.c", "stdio",
  "4 MiB through tee, verified as two identical copies", argv=["4"],
  oracle="stderr", stdio="tee", stdio_reference=True,
  bulk={"stream": "stdout", "bytes_key": "STREAM_BYTES", "sha_key": "STREAM_SHA256"},
  stdio_expect={"tee_copy_matches_captured": True, "captured_equals_reference": True},
  expect={"STREAM_BYTES": "4194304", "STREAM_COMPLETE": "yes"}, timeout=180.0,
  notes="At volume, `tee` is a second consumer that can fall behind. Both copies "
        "and the reference capture must agree byte for byte.")
S("linux-stdio-earlyclose-4mib", "io_stream.c", "stdio",
  "a consumer that closes after 64 KiB of a 4 MiB stream, killing the writer",
  argv=["4"], oracle="stderr", stdio="earlyclose", stdio_limit=65536,
  stdio_reference=True, signal="SIGPIPE", exit=None, result=False,
  stdio_expect={"consumer_reached_limit": True,
                "consumer_closed_after_bytes": 65536,
                "captured_is_prefix_of_reference": True},
  expect={"STREAM_REQUESTED_BYTES": "4194304"}, timeout=180.0,
  notes="THE loud case, and the counterpart to linux-stdio-shape-earlyclose. "
        "4 MiB does not fit in a pipe buffer, so when the consumer goes away the "
        "writer is killed by SIGPIPE mid-stream and never prints its attestation "
        "or a RESULT line. What was captured must still be a genuine PREFIX of "
        "the full stream -- a truncated stream and a reordered one have the same "
        "length, so the prefix relation is the check and the length is not.")
S("linux-stdio-cmdsub-oracle", "self_report.c", "stdio",
  "the oracle stream itself passes through a command substitution",
  stdio="cmdsub", stdio_reference=True,
  stdio_expect={"captured_equals_reference": False,
                "captured_equals_reference_rstrip_newlines": True,
                "trailing_newlines_lost": 1},
  expect={"ARGC": "1", "ARGV0_PRESENT": "yes", "DOUBLE_MATH": "1.000000"},
  notes="The KEY=VALUE contract has to survive the most common capture idiom "
        "there is. It does: the final newline is stripped and the last line is "
        "still parseable, which is why the oracle parser must not require a "
        "trailing newline. Declared, rather than left to luck.")
S("linux-stdio-binary-tee", "io_binary_stdout.c", "stdio",
  "all 256 byte values through tee, which must not alter one of them",
  oracle="stderr", stdio="tee", stdio_reference=True,
  bulk={"stream": "stdout", "bytes_key": "BINARY_BYTES", "fnv_key": "BINARY_FNV1A"},
  stdio_expect={"tee_copy_matches_captured": True, "captured_equals_reference": True},
  expect={"BINARY_BYTES": "256"},
  notes="The lossless half of the binary pair. tee moves NUL, 0x1A, CR and "
        "invalid UTF-8 through unchanged, and both copies are checked.")
S("linux-stdio-binary-cmdsub", "io_binary_stdout.c", "stdio",
  "all 256 byte values through a command substitution, which loses the NULs",
  oracle="stderr", stdio="cmdsub", stdio_reference=True,
  stdio_expect={"captured_equals_reference": False,
                "captured_equals_reference_nuls_removed_rstrip_newlines": True},
  expect={"BINARY_BYTES": "256"},
  notes="The lossy half. A shell variable cannot hold a NUL byte, so the shape "
        "silently deletes them and strips the trailing newlines. Declared as an "
        "exact relation to the reference capture -- remove the NULs, strip the "
        "trailing newlines, and the two are equal -- so the damage is measured "
        "rather than merely expected. No digest check: the specimen attested to "
        "what it wrote, and this shape did not deliver that.")
S("linux-stdio-both-to-files", "io_both.c", "stdio",
  "both streams to separate regular files, so neither can mask the other",
  stdio="file", expect={"OUT_TOTAL": "8"},
  notes="linux-io-both-streams captures both through pipes and can therefore "
        "assert only the per-stream content, never the interleaving. Two files "
        "make each stream independently complete and independently checkable.")
S("linux-stdio-slow-to-file", "io_stream_slow.c", "stdio",
  "output that arrives in bursts, into a regular file", argv=["8", "120", "500"],
  oracle="stderr", stdio="file", duration="seconds",
  bulk={"stream": "stdout", "bytes_key": "SLOW_BYTES", "sha_key": "SLOW_SHA256"},
  expect={"SLOW_TICKS_REQUESTED": "8", "SLOW_TICKS_WRITTEN": "8",
          "SLOW_GAP_MS": "120", "SLOW_TAIL_MS": "500", "SLOW_BYTES": "262144",
          "SLOW_TAIL_ELAPSED": "yes"}, timeout=120.0,
  notes="Pacing survives to a file: eight bursts and half a second of silence "
        "with the fd still open. Half the ticks of linux-io-stream-slow-paced so "
        "the shape is covered without paying for the duration twice.")
S("linux-stdio-stdin-required-devnull", "io_stdin.c", "stdio",
  "a program that REQUIRES stdin, launched with /dev/null",
  stdio="devnull-stdin", result=False,
  expect={"STDIN_BYTES": "0", "READ_TO_EOF": "yes", "STDIN_NOT_EMPTY": "no",
          "RESULT": "FAIL"},
  notes="RESULT=FAIL is the correct outcome and the specimen is behaving "
        "perfectly: it ran, found its environment did not meet its stated "
        "requirement, and said so on the stream instead of hanging or crashing. "
        "An exit code of 0 with RESULT=FAIL is exactly the case a consumer that "
        "reads only the exit code cannot see.")

# ---- filesystem ----------------------------------------------------------
S("linux-fs-tmpfile-mkstemp", "fs_tmpfile.c", "filesystem",
  "a temporary file created and removed under TMPDIR",
  expect={"MKSTEMP": "yes", "WROTE": "yes", "READ_BACK_OK": "yes", "UNLINKED": "yes",
          "GONE": "yes", "LEAVES_NO_TRACE": "yes"},
  caps=["a writable TMPDIR"], effects=["none that survive the run"])
S("linux-fs-persistent-state", "fs_persist.c", "filesystem",
  "state that must survive between two launches", runs=2,
  expect={"OPEN_APPEND": "yes", "FLUSH_OK": "yes", "AT_LEAST_ONE_RUN": "yes"},
  effects=["appends one line to state.dat per run"],
  caps=["a writable directory that persists between launches"],
  notes="Run twice by the runner: RUN_COUNT must read 1 then 2.")
S("linux-fs-cwd-relative-asset", "fs_cwd.c", "filesystem",
  "a working-directory assumption: ./assets/data.txt",
  files={"assets/data.txt": "relative-asset-v1\n"},
  expect={"ASSET_OPENED": "yes", "ASSET_CONTENT": "relative-asset-v1",
          "ASSET_CONTENT_OK": "yes"},
  caps=["the working directory is where the asset is"],
  notes="Breaks the moment something launches it from a different directory.")
S("linux-fs-flock-contention", "fs_flock.c", "filesystem",
  "BSD advisory lock contention between parent and child",
  procbeh="forks-one-child", effects=["creates lockfile"],
  expect={"OPEN_LOCKFILE": "yes", "FLOCK_EX": "yes", "CHILD_STATUS": "0",
          "CHILD_BLOCKED_AS_EXPECTED": "yes", "UNLOCK": "yes"})
S("linux-fs-fcntl-record-lock", "fs_fcntl_lock.c", "filesystem",
  "POSIX record locks on disjoint byte ranges",
  procbeh="forks-one-child", effects=["creates record.dat, 4096 bytes"],
  expect={"LOCK_0_127": "yes", "CHILD_STATUS": "0",
          "CONFLICT_DENIED_AND_FREE_GRANTED": "yes"})
S("linux-fs-mmap-file", "fs_mmap_file.c", "filesystem",
  "a file written through a shared mmap", effects=["creates mapped.dat, 64 KiB"],
  expect={"MMAP": "yes", "MSYNC": "yes", "MUNMAP": "yes", "READ_BACK": "yes"},
  notes="MAP_HASH and FILE_HASH must be equal, which the runner checks.")
S("linux-fs-mmap-large-anon", "fs_mmap_large.c", "filesystem",
  "a 1 GiB anonymous reservation, sparsely touched",
  expect={"MMAP": "ok", "RESERVE_BYTES": "1073741824", "PAGES_TOUCHED": "64",
          "LARGE_MAP_AVAILABLE": "yes", "MUNMAP": "yes"},
  caps=["1 GiB of address space (not of RAM)"], timeout=120.0)
S("linux-fs-posix-shm", "fs_shm.c", "filesystem",
  "POSIX shared memory shared with a child", procbeh="forks-one-child",
  expect={"SHM_OPEN": "ok", "SHM_MAPPED": "yes", "CHILD_EXIT": "0",
          "CHILD_WROTE_THROUGH_SHM": "yes", "SHM_UNLINK": "yes",
          "SHM_AVAILABLE": "yes"},
  caps=["/dev/shm"], effects=["creates and unlinks a name under /dev/shm"])
S("linux-fs-symlink", "fs_symlink.c", "filesystem", "creates and follows a symlink",
  effects=["creates target.txt and link.txt"],
  expect={"SYMLINK_CREATED": "yes", "READLINK": "target.txt", "LSTAT_IS_LINK": "yes",
          "STAT_IS_REGULAR": "yes", "FOLLOWED_CONTENT": "yes"})
S("linux-fs-directory-tree", "fs_dirtree.c", "filesystem",
  "builds and walks a 46-entry directory tree",
  effects=["creates tree/ with 6 directories and 40 files"],
  expect={"DIRS_FOUND": "6", "FILES_FOUND": "40", "TREE_SHAPE": "yes"})
S("linux-fs-atomic-rename", "fs_atomic_rename.c", "filesystem",
  "the fsync plus rename durability pattern",
  effects=["leaves data.final, removes data.tmp"],
  expect={"WRITE_TMP": "yes", "FSYNC_FILE": "yes", "RENAME": "yes", "FSYNC_DIR": "yes",
          "TMP_GONE": "yes", "FINAL_CONTENT": "yes"})
S("linux-fs-path-environment", "fs_paths.c", "filesystem",
  "reports which environment-directed directories it can write to",
  expect={"HOME_WRITABLE": "yes", "TMPDIR_OR_TMP_WRITABLE": "yes",
          "CWD_DOT_WRITABLE": "yes", "CWD_USABLE": "yes"},
  notes="The runner supplies HOME, TMPDIR and the XDG variables; all must be writable.")
S("linux-fs-readonly-probe", "fs_readonly_probe.c", "filesystem",
  "probes three locations it should not be able to write",
  expect={"USR_WRITE": "denied", "ETC_WRITE": "denied", "ROOT_WRITE": "denied",
          "SURVIVED_ALL_PROBES": "yes"},
  notes="Declared for an ordinary unprivileged user. It reports the policy it is "
        "under; it does not assert what that policy ought to be.")

# ---- interface: arguments and environment --------------------------------
S("linux-arg-none", "arg_report.c", "interface", "no arguments at all",
  expect={"ARGC": "1", "ARGV_NULL_TERMINATED": "yes"})
S("linux-arg-basic-flags", "arg_report.c", "interface", "ordinary flags and values",
  argv=["--flag", "-x", "value", "7"],
  expect={"ARGC": "5", "ARG_1_LEN": "6", "ARG_1_HEX": "2d2d666c6167",
          "ARG_4_LEN": "1", "ARG_4_HEX": "37"})
S("linux-arg-empty-string", "arg_report.c", "interface", "an empty-string argument",
  argv=["", "after", ""],
  expect={"ARGC": "4", "ARG_1_LEN": "0", "ARG_1_HEX": "", "ARG_3_LEN": "0"},
  notes="Anything that rebuilds argv through a shell string loses these.")
S("linux-arg-with-spaces", "arg_report.c", "interface",
  "arguments containing spaces, tabs and quotes",
  argv=["two words", " leading", "trailing ", "a\tb", "it is \"quoted\""],
  expect={"ARGC": "6", "ARG_1_LEN": "9", "ARG_1_HEX": "74776f20776f726473",
          "ARG_2_LEN": "8", "ARG_3_LEN": "9", "ARG_4_LEN": "3", "ARG_4_HEX": "610962"},
  notes="Declared by byte length and hex so whitespace damage is unambiguous.")
S("linux-arg-unicode", "arg_report.c", "interface", "UTF-8 arguments outside ASCII",
  argv=["café", "日本語", "emoji-\U0001F600", "Ωmega"],
  expect={"ARGC": "5", "ARG_1_LEN": "5", "ARG_1_HEX": "636166c3a9",
          "ARG_2_LEN": "9", "ARG_2_HEX": "e697a5e69cace8aa9e",
          "ARG_3_LEN": "10", "ARG_4_LEN": "6", "ARG_4_HEX": "cea96d656761"})
S("linux-arg-many-512", "arg_report.c", "interface", "512 arguments",
  argv=["a%03d" % i for i in range(512)],
  expect={"ARGC": "513", "ARG_1_LEN": "4", "ARG_512_LEN": "4"})
S("linux-arg-huge-100k", "arg_report.c", "interface", "one 100000-byte argument",
  argv=["x" * 100000],
  expect={"ARGC": "2", "ARG_1_LEN": "100000",
          "ARG_1_HEX": "(elided,100000 bytes)"},
  caps=["an argument vector of at least 128 KiB"])
S("linux-env-declared-present", "env_report.c", "interface",
  "reads declared environment variables",
  argv=["LEXE_WORKLOAD_TOKEN", "LEXE_WORKLOAD_EMPTY", "PATH"],
  env={"LEXE_WORKLOAD_TOKEN": "token-value-1", "LEXE_WORKLOAD_EMPTY": ""},
  expect={"ENV_LEXE_WORKLOAD_TOKEN_PRESENT": "yes",
          "ENV_LEXE_WORKLOAD_TOKEN_LEN": "13",
          "ENV_LEXE_WORKLOAD_TOKEN_HEX": "746f6b656e2d76616c75652d31",
          "ENV_LEXE_WORKLOAD_EMPTY_PRESENT": "yes",
          "ENV_LEXE_WORKLOAD_EMPTY_LEN": "0",
          "ENV_PATH_PRESENT": "yes"},
  notes="An empty-but-present variable is not the same as an absent one.")
S("linux-env-absent", "env_report.c", "interface",
  "reports a variable that was never set",
  argv=["LEXE_WORKLOAD_NOT_SET", "LEXE_WORKLOAD_TOKEN"],
  expect={"ENV_LEXE_WORKLOAD_NOT_SET_PRESENT": "no",
          "ENV_LEXE_WORKLOAD_TOKEN_PRESENT": "no"})
S("linux-env-unicode-value", "env_report.c", "interface",
  "a UTF-8 environment value", argv=["LEXE_WORKLOAD_UNICODE"],
  env={"LEXE_WORKLOAD_UNICODE": "naïve-日本"},
  expect={"ENV_LEXE_WORKLOAD_UNICODE_PRESENT": "yes",
          "ENV_LEXE_WORKLOAD_UNICODE_LEN": "13",
          "ENV_LEXE_WORKLOAD_UNICODE_HEX": "6e61c3af76652de697a5e69cac"})
S("linux-env-emptied", "env_empty.c", "interface",
  "re-executes itself with an empty environment",
  expect={"PHASE": "two", "ENVIRON_COUNT": "0", "ENVIRON_EMPTY": "yes",
          "GETENV_PATH_PRESENT": "no"},
  procbeh="replaces-own-image")
S("linux-interface-argv0", "argv0.c", "interface",
  "compares argv[0] with /proc/self/exe",
  expect={"SELF_EXE_READABLE": "yes", "ARGV0_IS_ABSOLUTE": "yes",
          "ARGV0_EQUALS_SELF_EXE": "yes"},
  notes="Declared for a direct absolute-path launch. A launcher that copies, "
        "symlinks or renames the binary changes both answers.")

# ---- outcomes ------------------------------------------------------------
for _code in (0, 1, 42, 255):
    S("linux-outcome-exit-%d" % _code, "exit_code.c", "outcome",
      "exits with status %d after a complete run" % _code,
      argv=[str(_code)], exit=_code,
      expect={"EXIT_CODE_INTENDED": str(_code), "WORK_DONE": "yes"},
      notes="RESULT=PASS with exit %d: the non-zero status is the declared "
            "outcome, not a malfunction." % _code)
S("linux-outcome-atexit-order", "exit_atexit.c", "outcome",
  "atexit handlers run in reverse order after main returns", exit=7,
  expect={"REG1": "yes", "REG3": "yes", "EXPECTED_ORDER": "3,2,1"},
  notes="ATEXIT=3, ATEXIT=2, ATEXIT=1 must all appear AFTER the RESULT line.")
S("linux-run-bounded-500ms", "run_sleep.c", "outcome", "a bounded sub-second run",
  argv=["500"], duration="sub-second",
  expect={"SLEEP_REQUESTED_MS": "500", "SLEPT_AT_LEAST_REQUESTED": "yes",
          "DURATION_CLASS": "sub-second"})
S("linux-run-bounded-3s", "run_sleep.c", "outcome", "a bounded multi-second run",
  argv=["3000"], duration="seconds", timeout=60.0,
  expect={"SLEEP_REQUESTED_MS": "3000", "SLEPT_AT_LEAST_REQUESTED": "yes",
          "DURATION_CLASS": "seconds"})
S("linux-run-cpu-bound", "run_cpu.c", "outcome",
  "a deterministic CPU-bound run", argv=["50000000"], duration="seconds", timeout=120.0,
  expect={"ROUNDS": "50000000", "WORK_COMPLETED": "yes"},
  notes="CHECKSUM must be identical under every toolchain; that is the point.")

# ---- sockets -------------------------------------------------------------
S("linux-socket-unix-pair", "sock_pair.c", "sockets",
  "socketpair exchange with a child", procbeh="forks-one-child",
  expect={"SOCKETPAIR": "yes", "SENT_PING": "yes", "REPLY": "PONG",
          "GOT_PONG": "yes", "PEER_EXIT": "0"},
  notes="No network stack involved: this separates a denied network from a "
        "denied socket API.")
S("linux-socket-unix-named", "sock_unix_named.c", "sockets",
  "a named AF_UNIX socket in the working directory",
  procbeh="forks-one-child", effects=["creates and removes service socket wl.sock"],
  expect={"SOCKET": "yes", "BIND": "yes", "LISTEN": "yes", "ACCEPT": "yes",
          "RECEIVED": "HELLO-UNIX", "PAYLOAD_OK": "yes", "CLIENT_EXIT": "0",
          "SOCKFILE_REMOVED": "yes"},
  caps=["a writable directory that supports socket nodes"])
S("linux-socket-tcp-loopback", "sock_tcp.c", "sockets",
  "TCP over 127.0.0.1 on an ephemeral port", procbeh="forks-one-child",
  expect={"TCP_LOOPBACK": "ok", "RECEIVED": "HELLO-TCP", "CLIENT_EXIT": "0",
          "SURVIVED_NETWORK_ATTEMPT": "yes"},
  caps=["loopback networking"],
  notes="Declared for an unconfined host. A runtime that denies networking will "
        "produce TCP_LOOPBACK=unavailable with a named failing stage and errno, "
        "which is a legitimate observation and not a specimen failure.")
S("linux-socket-udp-loopback", "sock_udp.c", "sockets",
  "one UDP datagram over loopback",
  expect={"UDP_LOOPBACK": "ok", "RECEIVED": "DGRAM-1",
          "SURVIVED_NETWORK_ATTEMPT": "yes"},
  caps=["loopback networking"])
S("linux-socket-name-resolution", "sock_resolve.c", "sockets",
  "resolver behaviour for a local name and a bogus one",
  expect={"LOCALHOST_RC_IS_ZERO": "yes", "LOCALHOST_ADDRS_NONZERO": "yes",
          "BOGUS_RC_IS_ZERO": "no", "ETC_HOSTS_READABLE": "yes",
          "SURVIVED_RESOLUTION": "yes"},
  caps=["/etc/hosts and the NSS configuration"],
  notes="Also a probe of what a confined filesystem view kept: without "
        "/etc/nsswitch.conf even localhost stops resolving.")

# ---- compound ------------------------------------------------------------
S("linux-compound-pipeline", "compound_pipeline.c", "compound",
  "a three-stage self-exec pipeline joined by pipes",
  procbeh="three-children-two-pipes", timeout=120.0,
  effects=["creates digest.out"],
  expect={"STAGES": "3", "BYTES_PER_STAGE": "262144", "PIPES": "yes",
          "PRODUCE_EXIT": "0", "TRANSFORM_EXIT": "0", "DIGEST_EXIT": "0",
          "DIGEST_FILE_PRESENT": "yes", "PIPELINE_BYTES": "262144",
          "PIPELINE_HASH_MATCHES": "yes", "PIPELINE_BYTES_MATCH": "yes"},
  notes="fork, exec, pipe, dup2, wait status, a file and a cross-process "
        "checksum in one specimen.")
S("linux-compound-unix-service", "compound_service.c", "compound",
  "a small threaded service over a named socket",
  cflags=["-pthread"], procbeh="four-threads-one-child-socket-shm",
  timeout=120.0, effects=["creates service.log, creates and removes service.sock"],
  expect={"SIGTERM_HANDLER": "yes", "LISTEN_SOCKET": "yes", "BIND": "yes",
          "LISTEN": "yes", "SHM_FALLBACK": "none", "REQUESTS_EXPECTED": "12",
          "REQUESTS_SERVED_AT_LEAST": "yes", "CLIENT_EXIT": "0",
          "SHUTDOWN_SIGNAL_SEEN": "yes", "CLIENT_ALL_ACKED": "yes",
          "SIGTERM_DELIVERED_TO_HANDLER": "yes", "LOG_PRESENT": "yes"},
  caps=["threads", "AF_UNIX sockets", "/dev/shm", "signals"],
  notes="Threads, sockets, signals, shared memory, fork and files at once.")

# ---- more ways to die ----------------------------------------------------
# The corpus had two deaths: a null write and an abort(). These are the other
# mechanisms, and they are not interchangeable -- an illegal instruction, an
# integer division by zero, a mapping whose file was truncated, an exhausted
# stack and a failed assertion arrive through five different paths. Every one is
# provoked genuinely rather than by raise(), because raise() proves only that
# raise() works.
S("linux-outcome-sigill", "crash_modes.c", "outcome",
  "dies from SIGILL on a genuine undefined instruction", argv=["ill"],
  signal="SIGILL", exit=None,
  expect={"CRASH_MODE": "ill", "FAULT_KIND": "illegal-instruction",
          "EXPECT_DEATH": "sigill"},
  notes="__builtin_trap emits ud2. The fault comes from the CPU, not from libc.")
S("linux-outcome-sigfpe", "crash_modes.c", "outcome",
  "dies from SIGFPE on integer division by zero", argv=["fpe"],
  signal="SIGFPE", exit=None,
  expect={"CRASH_MODE": "fpe", "FAULT_KIND": "integer-division-by-zero",
          "EXPECT_DEATH": "sigfpe"},
  notes="Both operands are volatile so no optimiser can fold the division away. "
        "SIGFPE from an INTEGER divide surprises people who expect it to be "
        "about floating point.")
S("linux-outcome-sigbus", "crash_modes.c", "outcome",
  "dies from SIGBUS touching a mapping whose file was truncated", argv=["bus"],
  signal="SIGBUS", exit=None, effects=["creates bus.dat"],
  expect={"CRASH_MODE": "bus", "FAULT_KIND": "mapping-truncated-under-us",
          "SETUP_OK": "yes", "EXPECT_DEATH": "sigbus"},
  notes="The address stays mapped; the page behind it stops existing. This is "
        "what a program gets when the file it mapped is replaced underneath it.")
S("linux-outcome-stack-overflow", "crash_modes.c", "outcome",
  "dies from SIGSEGV by exhausting its stack", argv=["stack"],
  signal="SIGSEGV", exit=None, timeout=120.0,
  expect={"CRASH_MODE": "stack", "FAULT_KIND": "stack-exhaustion",
          "EXPECT_DEATH": "sigsegv-stack-guard"},
  notes="A guard-page fault, not a null dereference: same signal, entirely "
        "different cause, and the address is nowhere near zero. Anything that "
        "classifies crashes by the faulting address gets these two confused.")
S("linux-outcome-assert-failure", "crash_modes.c", "outcome",
  "dies from SIGABRT through a failed assert()", argv=["assert"],
  signal="SIGABRT", exit=None,
  expect={"CRASH_MODE": "assert", "FAULT_KIND": "failed-assertion",
          "EXPECT_DEATH": "sigabrt-assert"},
  notes="assert() writes its own message to stderr before aborting, so this "
        "specimen dies with diagnostic output on a stream that is not the "
        "oracle's. Same signal as linux-outcome-abort, different route.")

# ---- exit codes that mean something else to somebody --------------------
# 0, 1, 42 and 255 were already here. These are the ones that get MISREAD,
# which is the property: 126 and 127 are what a shell invents when it cannot
# run a program at all, and 128+n is what a shell invents for death by signal n.
# A program that legitimately exits 137 is indistinguishable, from the status
# alone, from one the OOM killer reached -- and only one of them is a problem.
for _code, _why in ((2, "the conventional 'wrong usage' status"),
                    (77, "a plain application-defined status in the middle of "
                         "the range"),
                    (126, "what a shell reports when a file exists but cannot be "
                          "executed -- here it is the program's own chosen status"),
                    (127, "what a shell reports for 'command not found' -- here "
                          "the command was found and chose this"),
                    (128, "the boundary above which a shell starts reading a "
                          "status as a signal number"),
                    (130, "128+SIGINT: indistinguishable from Ctrl-C to anything "
                          "that only sees the status"),
                    (137, "128+SIGKILL: indistinguishable from an OOM kill"),
                    (200, "well above any signal encoding and still perfectly "
                          "legal")):
    S("linux-outcome-exit-%d" % _code, "exit_code.c", "outcome",
      "exits with status %d after a complete run" % _code,
      argv=[str(_code)], exit=_code,
      expect={"EXIT_CODE_INTENDED": str(_code), "WORK_DONE": "yes"},
      notes="RESULT=PASS with exit %d. %s. The specimen ran to completion; the "
            "status is its declared outcome and nothing died." % (_code, _why))

# ---- threads beyond the count -------------------------------------------
S("linux-thread-tls", "thread_modes.c", "process",
  "thread-local storage: four threads, four private copies",
  cflags=["-pthread"], argv=["tls"], procbeh="multi-threaded",
  expect={"THREAD_MODE": "tls", "THREADS_STARTED": "yes",
          "MAIN_TLS_AFTER_JOINS": "7", "MAIN_TLS_UNDISTURBED": "yes",
          "TLS_SEEN_0": "1000", "TLS_SEEN_1": "1001", "TLS_SEEN_2": "1002",
          "TLS_SEEN_3": "1003", "TLS_ALL_DISTINCT": "yes"},
  notes="The TLS model is a compiler decision, which is why this one is worth a "
        "differential: initial-exec and general-dynamic generate different code "
        "and the answer must not change.")
S("linux-thread-detached", "thread_modes.c", "process",
  "a detached thread nobody joins, which finishes before the process does",
  cflags=["-pthread"], argv=["detached"], procbeh="multi-threaded",
  duration="sub-second",
  expect={"THREAD_MODE": "detached", "DETACH_ATTR": "yes",
          "DETACHED_STARTED": "yes", "DETACHED_MARKER": "d00d",
          "DETACHED_WORK_COMPLETED": "yes", "NEVER_JOINED": "yes"})
S("linux-thread-main-exits-first", "thread_modes.c", "process",
  "main returns while a detached thread is still working, so the work is lost",
  cflags=["-pthread"], argv=["mainexits"], procbeh="multi-threaded",
  expect={"THREAD_MODE": "mainexits", "DETACHED_STARTED": "yes",
          "WORK_UNFINISHED_AT_EXIT": "yes"},
  notes="The counterpart to linux-thread-detached and the same source: there the "
        "process waits and the work completes, here it does not and the work "
        "vanishes with the process. Exit 0 either way, which is the point.")
S("linux-thread-crash-off-main", "thread_modes.c", "process",
  "a fault in a NON-main thread kills the whole process",
  cflags=["-pthread"], argv=["crash"], procbeh="multi-threaded",
  signal="SIGSEGV", exit=None, timeout=60.0,
  expect={"THREAD_MODE": "crash", "FAULT_KIND": "null-write-in-a-non-main-thread",
          "EXPECT_DEATH": "sigsegv-off-main-thread"},
  notes="The main thread is healthy and doing nothing wrong throughout. Anything "
        "that watches only the main thread sees a process that was fine and then "
        "was not.")
S("linux-thread-fork-in-threaded", "thread_modes.c", "process",
  "fork() from a threaded process: the child gets exactly one thread",
  cflags=["-pthread"], argv=["forkinthread"], procbeh="multi-threaded-and-forks",
  expect={"THREAD_MODE": "forkinthread", "PARENT_THREADS_STARTED": "yes",
          "FORK_OK": "yes", "REAPED": "yes", "CHILD_EXIT": "21",
          "CHILD_EXIT_21": "yes", "CHILD_THREAD_COUNT": "1",
          "CHILD_ROLE": "forked-from-threaded"},
  notes="However many threads the parent had, the child has one, and any lock "
        "another thread was holding is frozen in the child for ever. The child "
        "here does only async-signal-safe work for exactly that reason.")
S("linux-thread-condvar-handoff", "thread_modes.c", "process",
  "a real producer/consumer handoff over a condition variable",
  cflags=["-pthread"], argv=["condvar"], procbeh="multi-threaded",
  expect={"THREAD_MODE": "condvar", "CONSUMER_STARTED": "yes",
          "ITEMS_PRODUCED": "64", "CONSUMED_SUM": "2080", "SUM_IS_2080": "yes"},
  notes="64 items handed across, summed on the other side. A lost or duplicated "
        "wakeup changes the sum, so the total is the check rather than a count "
        "of iterations.")

# ---- C++, as an axis rather than a footnote ------------------------------
# Two C++ specimens of one program made "C/C++" a dimension in name only. This
# source is built under four language standards and reports which it got, so
# __cplusplus differs per specimen BY DESIGN and everything else must not.
for _std, _val in (("c++11", "201103"), ("c++14", "201402"),
                   ("c++17", "201703"), ("c++20", "202002")):
    S("linux-cxx-core-%s" % _std.replace("+", "p"), "cxx_core.cpp", "linkage",
      "the C++ runtime surface under -std=%s" % _std,
      cflags=["-std=%s" % _std],
      elf={"needed_contains": ["libstdc++.so.6"]},
      expect={"CXX_STANDARD": _val, "STATIC_INIT_ORDER": "12",
              "STATIC_INIT_IN_DECLARATION_ORDER": "yes",
              "TYPEID_MATCHES_DYNAMIC_TYPE": "yes",
              "TYPEID_DISTINGUISHES_SIBLINGS": "yes",
              "DYNAMIC_CAST_DOWN_SUCCEEDS": "yes",
              "DYNAMIC_CAST_SIDEWAYS_FAILS": "yes",
              "VIRTUAL_DISPATCH_IS_2": "yes",
              "EXCEPTION_CAUGHT_BY_BASE_REF": "yes",
              "EXCEPTION_WHAT": "deliberate",
              "DESTRUCTOR_RAN_DURING_UNWIND": "yes",
              "SORTED": "alpha,beta,gamma", "MAP_SIZE": "3", "MAP_ALPHA": "5",
              "LAMBDA_RESULT": "133", "LAMBDA_THROUGH_STD_FUNCTION": "yes",
              "DESTRUCTOR_CALLS": "1"},
      caps=["libstdc++"],
      notes="RTTI, dynamic_cast, unwinding with destructors, containers and a "
            "lambda through std::function. CXX_STANDARD is the only key that "
            "differs across the four; if any other one moves, the behaviour "
            "depended on the standard and the corpus needs to know.")
S("linux-cxx-so-exception", "cxx_so_throw.cpp", "linkage",
  "an exception thrown in a shared library and caught in the executable",
  cflags=["-L{LIBDIR}", "-lthrower", "-Wl,--enable-new-dtags",
          "-Wl,-rpath,$ORIGIN/../lib"],
  stage="origin", argv=["caught"],
  elf={"needed_contains": ["libthrower.so", "libstdc++.so.6"],
       "runpath": "$ORIGIN/../lib"},
  expect={"MODE": "caught", "TYPEINFO_UNIFIED_ACROSS_SO": "yes",
          "CAUGHT_STD_RUNTIME_ERROR_FROM_SO": "yes",
          "RUNTIME_WHAT": "from-the-library",
          "CAUGHT_BY_BASE_REFERENCE": "yes", "DYNAMIC_CAST_ACROSS_SO": "yes",
          "CUSTOM_CODE": "42", "CUSTOM_WHAT": "custom-from-the-library",
          "CAUGHT_EXACT_DERIVED_TYPE": "yes", "SCOPE_CODE": "77",
          "LIBRARY_DESTRUCTORS_RUN": "1", "UNWOUND_THROUGH_THE_LIBRARY": "yes",
          "CAUGHT_NON_CLASS_EXCEPTION": "yes", "INT_EXCEPTION_VALUE": "1234"},
  caps=["libstdc++", "relocatable-directory-tree"],
  notes="The C++ ABI's most load-bearing cross-module guarantee, and the one a "
        "packaging step is most likely to break by giving the library its own "
        "copy of the runtime. Identity of typeinfo is compared across the "
        "boundary; the mangled NAME is never asserted, because that would be "
        "asserting the compiler's mangling scheme instead.")
S("linux-cxx-so-exception-uncaught", "cxx_so_throw.cpp", "outcome",
  "an exception from a shared library escapes main and std::terminate aborts",
  cflags=["-L{LIBDIR}", "-lthrower", "-Wl,--enable-new-dtags",
          "-Wl,-rpath,$ORIGIN/../lib"],
  stage="origin", argv=["uncaught"], signal="SIGABRT", exit=None,
  elf={"needed_contains": ["libthrower.so"]},
  expect={"MODE": "uncaught", "EXCEPTION_SOURCE": "shared-library",
          "EXPECT_DEATH": "sigabrt-std-terminate"},
  caps=["libstdc++"],
  notes="Same binary as linux-cxx-so-exception, one argument different. "
        "std::terminate writes 'terminate called after throwing...' to stderr "
        "and aborts, so this dies with diagnostics on a stream the oracle is "
        "not on. Declared as a death so it stays distinguishable from the "
        "accident it looks like.")

# ---- filenames are byte strings -----------------------------------------
# The corpus declares ARGUMENTS containing spaces, Unicode and quotes. A FILENAME
# is a different surface: it goes through the directory entry, readdir, and every
# path-joining and quoting layer in between.
for _fid, _name, _prop in (
        ("spaces", "two words in a name.txt", "a filename containing spaces"),
        ("unicode", "café-日本-Ωmega.txt", "a UTF-8 filename outside ASCII"),
        ("leading-dash", "-not-an-option.txt",
         "a filename that begins with a dash"),
        ("shell-metachars", 'quote"and$dollar`and;semi.txt',
         "a filename full of shell metacharacters"),
        ("newline", "line-one\nline-two.txt",
         "a filename containing a newline, which is legal and ruins line-based "
         "tooling")):
    S("linux-fs-name-%s" % _fid, "fs_names.c", "filesystem", _prop,
      argv=[_name],
      expect={"NAME_LEN": str(len(_name.encode())),
              "NAME_HEX": _name.encode().hex(),
              "NAME_NON_EMPTY": "yes", "CREATED": "yes", "LSTAT_OK": "yes",
              "IS_REGULAR": "yes", "REOPENED": "yes",
              "CONTENT_ROUNDTRIP": "yes",
              "CONTENT_DELIMITER": "<<<LEXE-FS-NAME-PAYLOAD>>>",
              "OPENDIR": "yes", "FOUND_BY_EXACT_BYTES_IN_READDIR": "yes",
              "UNLINKED": "yes", "GONE": "yes"},
      effects=["creates and removes one file with an awkward name"],
      notes="Declared by byte length and by hex, never by appearance, so a "
            "mangled name is unambiguous. The file is located in the directory "
            "by an exact byte comparison of the entry, not by a pattern.")

# ---- a large memory image that is small on disk --------------------------
S("linux-format-large-bss", "big_bss.c", "format",
  "256 MiB of .bss: a large program that occupies almost nothing on disk",
  expect={"BSS_BYTES": "268435456", "STRIDE_BYTES": "1048576",
          "PAGES_PROBED": "256", "BSS_READS_AS_ZERO": "yes",
          "WRITEBACK_SUM": "32640", "PAGES_ARE_DISTINCT": "yes"},
  caps=["256 MiB of anonymous memory"], timeout=120.0,
  notes="The opposite shape to linux-format-large-binary's 48 MiB of .data. "
        "Together they are what makes 'file size is not memory size' measurable: "
        "compare binary.size_bytes across the two.")

# ---- exec by name, through PATH -----------------------------------------
S("linux-proc-exec-path-lookup", "exec_path.c", "process",
  "execvp of a bare name found on PATH", stage="helper", argv=["helper_child"],
  env={"PATH": "{BINDIR}:/usr/bin:/bin"}, exit=29, result=False,
  procbeh="replaces-own-image",
  expect={"TARGET_NAME": "helper_child", "TARGET_NAME_HAS_NO_SLASH": "yes",
          "PATH_PRESENT": "yes", "PHASE": "pre-exec", "LOOKUP": "execvp",
          "CHILD_ROLE": "exec-path", "CHILD_ARGC": "3",
          "CHILD_EXIT_INTENT": "29"},
  notes="Every other exec specimen names an absolute path, so until now nothing "
        "in the corpus depended on PATH being right -- while real software "
        "depends on it constantly. The exit status proves WHICH program took "
        "over; the looked-up name alone would not.")

# ---- locale: a claim about the host --------------------------------------
S("linux-env-locale-utf8", "env_locale.c", "interface",
  "a UTF-8 locale that this host does have", argv=["C.UTF-8"],
  expect={"REQUESTED_LOCALE": "C.UTF-8", "C_LOCALE_AVAILABLE": "yes",
          "C_LOCALE_IS_SINGLE_BYTE": "yes",
          "REQUESTED_LOCALE_AVAILABLE": "yes", "MB_CUR_MAX": "6",
          "MULTIBYTE_IN_EFFECT": "yes", "SAMPLE_BYTES": "19",
          "SAMPLE_WIDE_CHARS": "13", "MBSTOWCS": "ok", "WCSTOMBS_OK": "yes",
          "UTF8_ROUNDTRIPS": "yes"},
  caps=["a UTF-8 locale"],
  notes="Multibyte text round-trips only when a multibyte locale is in effect. "
        "The same program under the C locale decodes the same bytes differently.")
S("linux-env-locale-absent", "env_locale.c", "interface",
  "a locale this host does not have, refused and survived",
  argv=["en_US.UTF-8"],
  expect={"REQUESTED_LOCALE": "en_US.UTF-8", "C_LOCALE_AVAILABLE": "yes",
          "REQUESTED_LOCALE_AVAILABLE": "no", "FELL_BACK_TO": "C",
          "MB_CUR_MAX_AFTER_REFUSAL": "1", "SURVIVED_MISSING_LOCALE": "yes"},
  notes="This host has exactly three locales and en_US.UTF-8 is not one of them. "
        "setlocale returning NULL is a fact about the MACHINE, not a fault in "
        "the program, and the corpus needs a specimen that demonstrates the "
        "difference rather than one that avoids the question.")
S("linux-env-locale-from-environment", "env_locale.c", "interface",
  "setlocale(LC_ALL, \"\"): whatever the environment says", argv=["-"],
  expect={"REQUESTED_LOCALE": "-", "ENV_LOCALE_ACCEPTED": "yes",
          "MB_CUR_MAX": "6", "MULTIBYTE_IN_EFFECT": "yes",
          "UTF8_ROUNDTRIPS": "yes"},
  notes="The single most environment-dependent call in the C library. The "
        "runner supplies LC_ALL=C.UTF-8; change that and every value below "
        "MB_CUR_MAX changes with it, which is why the locale name itself is an "
        "observation and not a deterministic key.")

# ---- GUI -----------------------------------------------------------------
# The ELF corpus had no GUI specimen at all. These run on the project's own
# namespaced private X server -- a private mount AND network namespace in which
# the developer's real display is not merely unbound but invisible. Raw Xlib,
# because a toolkit would put a dozen libraries and a settings daemon between
# the specimen and the property. What is asserted is the window's state read
# back from the SERVER, never a pixel and never a screenshot.
GUI_OK = {"XOPEN_DISPLAY": "ok", "WINDOW_CREATED": "yes",
          "WINDOW_VIEWABLE": "yes", "WINDOW_MAP_STATE": "viewable",
          "WINDOW_WIDTH": "320", "WINDOW_HEIGHT": "200",
          "GEOMETRY_AS_REQUESTED": "yes"}

S("linux-gui-window-mapped", "gui_window.c", "gui",
  "a top-level window, mapped, confirmed viewable by the X server",
  cflags=["-lX11"], argv=["map"], display="private", timeout=120.0,
  elf={"needed_contains": ["libX11.so.6"]},
  expect=dict(GUI_OK, GUI_MODE="map", DISPLAY_SET="yes", WINDOW_DESTROYED="yes"),
  caps=["an X display"], procbeh="gui-single-window",
  notes="map_state == IsViewable is the server agreeing the window is on "
        "screen. XMapWindow is asynchronous, so the specimen round-trips until "
        "the server answers rather than asking once and racing.")
S("linux-gui-no-display", "gui_window.c", "gui",
  "the same GUI binary with no display at all: refused, cleanly",
  cflags=["-lX11"], argv=["nodisplay"], display="none", exit=3,
  elf={"needed_contains": ["libX11.so.6"]},
  expect={"GUI_MODE": "nodisplay", "DISPLAY_SET": "no",
          "XOPEN_DISPLAY": "fail", "NEEDS": "an X display",
          "FAILED_AS_DECLARED": "yes"},
  notes="THE pair that matters, and the same binary as linux-gui-window-mapped: "
        "one difference in the environment, two fully declared outcomes. It is "
        "what makes 'the GUI program could not start' distinguishable from 'the "
        "GUI program was never run', which from the outside look identical.")
S("linux-gui-two-windows", "gui_window.c", "gui",
  "two top-level windows from one process", cflags=["-lX11"], argv=["twowin"],
  display="private", timeout=120.0, elf={"needed_contains": ["libX11.so.6"]},
  expect=dict(GUI_OK, GUI_MODE="twowin", SECOND_WINDOW_CREATED="yes",
              SECOND_WINDOW_VIEWABLE="yes", TWO_DISTINCT_WINDOWS="yes",
              TOP_LEVEL_WINDOWS="2"),
  caps=["an X display"], procbeh="gui-two-windows",
  notes="Anything that assumes one process means one window is wrong here, and "
        "so is anything that identifies an application by its window.")
S("linux-gui-long-running", "gui_window.c", "gui",
  "a window held up for two seconds, then taken down deliberately",
  cflags=["-lX11"], argv=["hold", "2000"], display="private",
  duration="seconds", timeout=180.0, elf={"needed_contains": ["libX11.so.6"]},
  expect=dict(GUI_OK, GUI_MODE="hold", HOLD_MS="2000",
              STILL_VIEWABLE_AFTER_HOLD="yes", WINDOW_DESTROYED="yes"),
  caps=["an X display"], procbeh="gui-long-running",
  notes="The shape of an actual application: it starts, it is on screen for a "
        "while, it exits when it decides to. The window is confirmed viewable "
        "again at the END of the hold, not only at the start.")
S("linux-gui-crash-with-window", "gui_window.c", "gui",
  "crashes with a window still mapped", cflags=["-lX11"], argv=["crash"],
  display="private", exit=139, result=False, timeout=120.0,
  elf={"needed_contains": ["libX11.so.6"]},
  expect={"GUI_MODE": "crash", "XOPEN_DISPLAY": "ok", "WINDOW_VIEWABLE": "yes",
          "FAULT_KIND": "null-write-with-a-window-mapped",
          "EXPECT_DEATH": "sigsegv-while-gui"},
  caps=["an X display"], procbeh="gui-crashes",
  notes="The X connection dies with the process and the server reaps the window. "
        "A console crash and a crash with a window up are not the same event to "
        "anything watching the display. DECLARED AS EXIT 139, NOT AS SIGSEGV, "
        "and that is not a weakening: the private display is reached through "
        "unshare plus bash, which report a signal as exit 128+n, and nothing "
        "downstream can tell that apart from a program that exited 139. The "
        "generator refuses a signal= declaration here rather than accepting 139 "
        "as if it were a signal. linux-outcome-sigsegv on the console is what "
        "proves signal death is observable; this specimen proves the crash "
        "happens with a window up, which is a different claim.")
S("linux-gui-orphan-window", "gui_window.c", "gui",
  "a child keeps the window after the launched process has exited",
  cflags=["-lX11"], argv=["orphan", "300"], display="private",
  display_hold_s=30.0, display_hold_until="gui_orphan.log",
  settle=1.0, timeout=180.0,
  elf={"needed_contains": ["libX11.so.6"]},
  expect={"GUI_MODE": "orphan", "XOPEN_DISPLAY": "ok", "FORK_OK": "yes",
          "PARENT_CLOSED_ITS_DISPLAY_BEFORE_FORK": "yes",
          "PARENT_EXITS_FIRST": "yes", "CHILD_OWNS_THE_WINDOW": "yes"},
  post={"gui_orphan.log": ["ORPHAN_WINDOW_VIEWABLE=yes",
                           "ORPHAN_SURVIVED_PARENT=yes", "ORPHAN_RESULT=PASS"]},
  caps=["an X display"], procbeh="gui-orphan",
  effects=["gui_orphan.log appears after the launched process has exited"],
  notes="The Linux counterpart of the Windows launcher-exits shape, and the "
        "reason a window on screen is not evidence that the process somebody "
        "started is still alive. The proof is the post-run file, because by the "
        "time the child does its work there is nothing left reading its stdout. "
        "The stage is held open after the launched process exits because pd_run "
        "kills Xvfb the instant the command it launched returns, so the orphan "
        "lost its display and then its namespace before it could do any work, "
        "and the specimen measured the harness rather than the program. A real "
        "X server does not die when one application exits. The hold is a "
        "CONDITION and not a duration: three seconds passed on an idle host and "
        "failed under load, eight seconds passed alone and failed again with "
        "twelve other specimens running, and each of those failures was the "
        "fixture reporting the state of the machine rather than the state of "
        "the program. It now waits for gui_orphan.log to appear, with 30 s only "
        "as a ceiling. Nothing is weakened by that: the declaration is still "
        "that the file exists and contains the declared lines, so if the orphan "
        "never writes it the wait expires and the specimen fails exactly as it "
        "should.")

# ---- a genuinely long run ------------------------------------------------
S("linux-run-long-10s", "run_sleep.c", "outcome",
  "a ten-second run: long enough that something will decide it has hung",
  argv=["10000"], duration="tens-of-seconds", timeout=120.0,
  expect={"SLEEP_REQUESTED_MS": "10000", "SLEPT_AT_LEAST_REQUESTED": "yes",
          "DURATION_CLASS": "seconds"},
  notes="The corpus topped out at three seconds, which is under every default "
        "timeout there is. Ten is over some of them. It costs ten seconds of "
        "wall time per generation and buys the only specimen that is slow "
        "enough to be mistaken for stuck.")

# --------------------------------------------------------------------------
# Compiler differentials (FORMAT/SPEC section 9).
#
# A meaningful SUBSET, not a cartesian product. Each entry names the assumption
# the second toolchain could break. Fields other than the toolchain are copied
# from the base specimen, so a differential and its base are directly comparable
# and the deterministic keys of both MUST agree -- if they do not, either the
# source has undefined behaviour or a compiler is wrong, and either way the
# fixture is not yet evidence.
# --------------------------------------------------------------------------

DIFFERENTIALS = [
    ("linux-format-dynamic-pie", ["gcc-O0", "clang-O0", "clang-O2"],
     "The control case under every toolchain: constant folding of the float "
     "expression and the default PIE/PIC decision differ between gcc and clang."),
    ("linux-proc-threads-4", ["gcc-O0", "clang-O0", "clang-O2"],
     "Threading depends on TLS model and atomics lowering, which differ between "
     "the two compilers and between -O0 and -O2."),
    ("linux-signal-catch-report", ["gcc-O0", "clang-O0", "clang-O2"],
     "volatile sig_atomic_t is only correct if the optimiser respects it; -O2 is "
     "where a wrong assumption about handler-visible state shows up."),
    ("linux-run-cpu-bound", ["gcc-O0", "clang-O0", "clang-O2"],
     "The checksum is pure integer arithmetic and must be bit-identical under "
     "every toolchain. A differing CHECKSUM means a miscompile or UB."),
    ("linux-outcome-sigsegv", ["gcc-O0", "clang-O2"],
     "A null dereference is undefined behaviour, and an optimiser is entitled to "
     "delete it. Whether the crash survives -O2 under clang is a real question, "
     "and a specimen that stops crashing is a broken fixture."),
    ("linux-io-bulk-stdout", ["gcc-O0", "clang-O2"],
     "8 MiB through stdio with a hash computed in the same loop: buffering and "
     "loop vectorisation both change here."),
    ("linux-compound-pipeline", ["gcc-O0", "clang-O2"],
     "The compound case, to confirm the whole process tree behaves the same when "
     "every stage is built by a different compiler."),
    ("linux-cxx-shared-runtime", ["clang-O2"],
     "clang++ against the same libstdc++: a different front end, the same C++ "
     "ABI and the same exception unwinder."),
    ("linux-format-static", ["clang-O2"],
     "Static linking pulls in different libc startup paths per toolchain."),
    ("linux-io-stream-4mib", ["clang-O2"],
     "The xorshift stream and the SHA-256 in specs/orc_bulk.h are hand-written "
     "integer code. If one byte of the stream or one digit of the digest differs "
     "under another toolchain, the header has undefined behaviour in it and every "
     "specimen that includes it is worthless. 4 MiB is the cheapest size that "
     "would show it."),
    # -O3 arrived with the rest of this wave. It is on the specimens where
    # automatic vectorisation and aggressive inlining could actually change the
    # answer, and NOT sprayed across the table: a differential that cannot fail
    # is not evidence, it is a bigger number.
    ("linux-format-dynamic-pie", ["gcc-O3", "clang-O3"],
     "The control case at -O3 under both compilers, so every other -O3 entry "
     "has a baseline to be compared against."),
    ("linux-run-cpu-bound", ["gcc-O3", "clang-O3"],
     "-O3 vectorises integer loops. The checksum is a pure integer reduction "
     "and must be bit-identical to the scalar result; if it is not, the "
     "arithmetic depended on something the language does not promise."),
    ("linux-io-stream-4mib", ["gcc-O3"],
     "The hand-written SHA-256 and xorshift in specs/orc_bulk.h are exactly the "
     "shape an -O3 vectoriser transforms most. One differing digest means the "
     "header has undefined behaviour in it and every bulk specimen is worthless."),
    ("linux-outcome-sigfpe", ["gcc-O3", "clang-O3"],
     "An integer division by zero is undefined behaviour and an optimiser is "
     "entitled to delete it. Both operands are volatile, which is what is being "
     "tested: a specimen that stops raising SIGFPE at -O3 is a broken fixture."),
    ("linux-outcome-stack-overflow", ["clang-O2", "gcc-O3"],
     "The whole fault depends on the recursion NOT being turned into a loop. "
     "Tail-call elimination is exactly what a second compiler at a higher "
     "optimisation level is most likely to do differently."),
    ("linux-outcome-sigill", ["clang-O2"],
     "__builtin_trap lowers to a different instruction sequence per compiler, "
     "and some lower it to a call rather than to ud2."),
    ("linux-thread-tls", ["clang-O2", "gcc-O3"],
     "__thread is lowered through a TLS model the compiler chooses -- "
     "initial-exec or general-dynamic -- and the two generate entirely "
     "different access sequences for the same source."),
    ("linux-cxx-core-cpp17", ["clang-O2"],
     "clang++ against the same libstdc++: a different front end, the same C++ "
     "ABI, and RTTI and unwinding that must agree with gcc's exactly."),
    ("linux-cxx-so-exception", ["clang-O2"],
     "The exception crosses a .so built by GCC into an executable built by "
     "clang. If the typeinfo is not unified the catch is skipped silently, and "
     "this is the only specimen that would notice."),
    ("linux-stdio-shape-pipe", ["clang-O2"],
     "The fd-shape prober under a second compiler: fstat, fcntl and lseek "
     "results are the kernel's and must not vary, so any difference here is a "
     "problem with the specimen rather than with the shape."),
    ("linux-io-binary-bulk-16mib", ["clang-O2"],
     "The histogram and the hazard placement write over the stream at absolute "
     "offsets across chunk boundaries, with mixed integer widths. Agreement "
     "under a second toolchain is what says that arithmetic is defined rather "
     "than merely working here."),
]


def expand_differentials():
    by_id = {s["id"]: s for s in SPECIMENS}
    for base_id, toolchains, reason in DIFFERENTIALS:
        base = by_id[base_id]
        for tc in toolchains:
            if tc == base["toolchain"]:
                continue
            clone = json.loads(json.dumps({k: v for k, v in base.items()
                                           if k != "stdin"}))
            clone["stdin"] = base["stdin"]
            clone["id"] = "%s--%s" % (base_id, tc)
            clone["toolchain"] = tc
            clone["differential_of"] = base_id
            clone["differential_reason"] = reason
            clone["property"] = base["property"] + " [%s]" % tc
            # -s and -g are toolchain-level decisions in the base entries; the
            # unstripped/stripped declarations must not be carried into a
            # toolchain whose flags contradict them.
            if tc.endswith("-O0"):
                clone["declared"]["elf"].pop("stripped", None)
                clone["declared"]["elf"].pop("has_symtab", None)
            SPECIMENS.append(clone)


expand_differentials()

# Extra cross-key rules that a single expect= value cannot express.
_by_id = {s["id"]: s for s in SPECIMENS}
_by_id["linux-fs-persistent-state"]["declared"]["expect_sequence"] = {"RUN_COUNT": ["1", "2"]}
for _sid in ("linux-fs-mmap-file",):
    _by_id[_sid]["declared"]["equal_keys"] = [["MAP_HASH", "FILE_HASH"]]
for _sid in ("linux-io-pipe-roundtrip",):
    _by_id[_sid]["declared"]["equal_keys"] = [["EXPECTED_HASH", "CHILD_HASH"]]
for _sid in list(_by_id):
    if _sid.startswith("linux-compound-pipeline"):
        _by_id[_sid]["declared"]["equal_keys"] = [["EXPECTED_HASH", "PIPELINE_HASH"]]


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

# The x86-64 Linux numbering. SIGBUS and SIGTRAP were missing until a specimen
# declared death by SIGBUS and the generator raised KeyError -- which reported a
# fixture as `generator-error` rather than telling anyone the table was short.
SIGNAMES = {"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5,
            "SIGABRT": 6, "SIGBUS": 7, "SIGFPE": 8, "SIGKILL": 9,
            "SIGUSR1": 10, "SIGSEGV": 11, "SIGUSR2": 12, "SIGPIPE": 13,
            "SIGALRM": 14, "SIGTERM": 15, "SIGCHLD": 17, "SIGXCPU": 24,
            "SIGXFSZ": 25, "SIGSYS": 31}


def subst(items, mapping):
    out = []
    for it in items:
        for k, v in mapping.items():
            it = it.replace("{%s}" % k, v)
        out.append(it)
    return out


def compile_cmd(spec, out, target, stagelib=None):
    tc = TOOLCHAINS[spec["toolchain"]]
    cxx = spec["language"] == "c++"
    driver = tc["cxx"] if cxx else tc["cc"]
    flags = (COMMON_CXX if cxx else COMMON_C) + tc["opt"]
    mapping = {"LIBDIR": os.path.join(out, "lib"),
               "STAGELIB": stagelib or os.path.join(out, "lib"),
               "OUT": out}
    srcs = [os.path.join(SPECS, s) for s in spec["sources"]]
    cmd = [driver] + flags + srcs + ["-o", target] + subst(spec["cflags"], mapping)
    if spec["id"].startswith("linux-fs-posix-shm") or "compound_service" in spec["sources"][0]:
        cmd += ["-lrt"]
    return cmd


def build_libs(out):
    libdir = os.path.join(out, "lib")
    os.makedirs(libdir, exist_ok=True)
    tc = TOOLCHAINS["gcc-O2"]
    records = []
    for lib in LIBS:
        target = os.path.join(libdir, lib["name"])
        cxx = lib.get("lang") == "c++"
        cmd = ([tc["cxx"] if cxx else tc["cc"]]
               + (COMMON_CXX if cxx else COMMON_C) + tc["opt"] + ["-shared", "-fPIC"]
               + [os.path.join(SPECS, s) for s in lib["src"]]
               + ["-o", target] + subst(lib["extra"], {"LIBDIR": libdir}))
        r = sh(cmd)
        records.append({"name": lib["name"], "language": lib.get("lang", "c"),
                        "command": " ".join(cmd),
                        "ok": r.returncode == 0,
                        "stderr": r.stderr.strip()[:2000],
                        "sha256": sha256_file(target) if os.path.exists(target) else None})
    return records


def build_helper(out):
    tc = TOOLCHAINS["gcc-O2"]
    target = os.path.join(out, "bin", "helper_child")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    cmd = ([tc["cc"]] + COMMON_C + tc["opt"] + [os.path.join(SPECS, "helper_child.c"),
                                                "-o", target])
    r = sh(cmd)
    return {"command": " ".join(cmd), "ok": r.returncode == 0,
            "stderr": r.stderr.strip()[:2000], "path": target,
            "sha256": sha256_file(target) if os.path.exists(target) else None}


def build_one(spec, out):
    stage = spec["stage"]
    if stage in ("rpath", "runpath", "origin"):
        stagedir = os.path.join(out, "stage", spec["id"])
        bindir = os.path.join(stagedir, "bin")
        stagelib = os.path.join(stagedir, "lib")
        os.makedirs(bindir, exist_ok=True)
        os.makedirs(stagelib, exist_ok=True)
        for lib in LIBS:
            src = os.path.join(out, "lib", lib["name"])
            if os.path.exists(src):
                shutil.copy2(src, stagelib)
        target = os.path.join(bindir, spec["id"])
    else:
        stagelib = None
        target = os.path.join(out, "bin", spec["id"])
        os.makedirs(os.path.dirname(target), exist_ok=True)
    cmd = compile_cmd(spec, out, target, stagelib)
    t0 = time.time()
    r = sh(cmd)
    record = {
        "toolchain": spec["toolchain"],
        "compiler": cmd[0],
        "compiler_version": None,
        "flags": cmd[1:],
        "command": " ".join(cmd),
        "ok": r.returncode == 0 and os.path.exists(target),
        "seconds": round(time.time() - t0, 2),
        "warnings": r.stderr.strip()[:4000],
        "target": target,
        "stage_dir": os.path.dirname(os.path.dirname(target)) if stagelib else None,
    }
    return record

# --------------------------------------------------------------------------
# Direct execution baseline
# --------------------------------------------------------------------------

BASE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "TERM": "dumb", "SHELL": "/bin/sh"}

# The largest stream over which run_once computes a per-run FNV-1a. 8 MiB is not
# an arbitrary round number: it is the size of linux-io-bulk-stdout, the only
# specimen that had a bulk stream before the volume family existed, so every
# value the index recorded before this limit existed is still recorded now.
FNV_STREAM_LIMIT = 8 * 1024 * 1024


def parse_oracle(text):
    kv, order, det, repeats = {}, [], [], []
    for line in text.split("\n"):
        if not line or "=" not in line:
            continue
        key, val = line.split("=", 1)
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        if key in kv and kv[key] != val:
            repeats.append(key)
        kv[key] = val
        order.append((key, val))
        if not key.startswith("OBS_"):
            det.append(line)
    return kv, order, det, repeats


# --------------------------------------------------------------------------
# Stdio shapes.
#
# A launcher once discarded the program's output entirely, so HOW a specimen's
# streams are connected earned its own axis. Every shape below is an ordinary
# thing a shell, a supervisor or a CI system does to a program every day; none of
# them is a trick. The specimen is the constant and the shape is the variable, so
# one source can report a different DETERMINISTIC answer under each of them --
# which is what makes this a matrix rather than eight near-copies.
#
# Two of these shapes TRANSFORM the stream, and that is the point of having them:
# a command substitution strips trailing newlines and an early-closing consumer
# truncates. Those are declared per specimen and verified against a reference
# capture of the same program through a plain pipe, so the transformation is a
# measured fact rather than an assumption about what the shell does.
# --------------------------------------------------------------------------

STDIO_SHAPES = {
    "pipe":
        "stdout and stderr are pipes the runner drains, stdin is a pipe carrying "
        "the declared input and then closed. The control shape, and what every "
        "other specimen in the corpus uses.",
    "file":
        "stdout and stderr are redirected to regular files, as `prog >out 2>err`. "
        "A regular file is seekable and glibc chooses FULL buffering for it "
        "rather than the line buffering it would pick for a terminal, so this is "
        "not merely a different destination.",
    "tee":
        "stdout goes through `tee` to a file AND onward to the runner, as "
        "`prog | tee out`. Two independent copies of one stream must be "
        "byte-identical; if they are not, something in the middle is editing it.",
    "cmdsub":
        "stdout is captured by a shell command substitution, `out=$(prog)`. This "
        "shape is LOSSY BY DESIGN: the shell strips every trailing newline and "
        "cannot carry NUL bytes at all. Declared and verified as a "
        "transformation of the reference capture.",
    "earlyclose":
        "the consumer reads a bounded prefix of stdout and then closes its end, "
        "as `prog | head -c N`. A specimen that keeps writing gets SIGPIPE. "
        "Implemented with a real pipe rather than a shell so the specimen's own "
        "wait status is exact instead of bash's 128+n encoding.",
    "devnull-stdin":
        "stdin is /dev/null: reads return EOF immediately and the fd is a "
        "character device. Indistinguishable from an empty pipe by byte count "
        "alone, which is why STDIN_KIND exists.",
    "file-stdin":
        "stdin is a regular file holding the declared input, as `prog <in.dat`. "
        "Seekable, unlike a pipe.",
    "closed-stdout":
        "fd 1 is closed outright, as `prog >&-`. Writing to it fails with EBADF. "
        "Run through `exec` so the shell is REPLACED by the specimen and the wait "
        "status is the specimen's own.",
}

# Shapes whose status for the specimen comes from bash's ${PIPESTATUS}/$? rather
# than from waitpid. bash encodes death-by-signal as 128+n, which it cannot tell
# apart from an exit code of 128+n, so these shapes are used only for specimens
# declared to exit normally with a code below 128.
SHELL_STATUS_SHAPES = {"tee", "cmdsub"}


# --------------------------------------------------------------------------
# The private display.
#
# docs/TESTING.md forbids any automated test putting a window on the developer's
# screen, and on WSLg that is not a matter of setting DISPLAY: /tmp/.X11-unix is
# mounted read-only with the user's real X0 in it, Xvfb's abstract socket lives
# in the network namespace, and a stale lock on the shared /tmp blocks display
# numbers that look free. scripts/lib/private-display.sh handles all three. It is
# used here unchanged rather than reimplemented, and the GUI specimens run inside
# a mount and network namespace where the user's display is not visible at all.
# --------------------------------------------------------------------------

DISPLAY_COUNTER = [140]
DISPLAY_LOCK = threading.Lock()


def next_display():
    with DISPLAY_LOCK:
        DISPLAY_COUNTER[0] += 1
        if DISPLAY_COUNTER[0] > 168:
            DISPLAY_COUNTER[0] = 141
        return DISPLAY_COUNTER[0]


def write_display_helper(out):
    path = os.path.join(out, "run_on_private_display.sh")
    with open(path, "w", newline="\n") as f:
        f.write("#!/bin/bash\n"
                "# Run a command on the project's namespaced private X server.\n"
                "# Exit 90 means the display could not be created here, which is\n"
                "# a fact about the host and is recorded as such.\n"
                "set -u\n"
                'source "%s"\n'
                "if ! pd_available; then\n"
                '  echo "PD_UNAVAILABLE=$PD_UNAVAILABLE_REASON" >&2\n'
                "  exit 90\n"
                "fi\n"
                'num="$1"; shift\n'
                'pd_run "$num" -- "$@"\n' % PD_LIB)
    os.chmod(path, 0o755)
    return {"path": path, "library": PD_LIB,
            "library_sha256": sha256_file(PD_LIB) if os.path.exists(PD_LIB) else None,
            "present": os.path.exists(PD_LIB)}


def _shape_dir(rundir):
    d = os.path.join(rundir, "stdio")
    os.makedirs(d, exist_ok=True)
    return d


def _read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


def _run(argv, timeout, **kw):
    """subprocess.run with a uniform (rc, stdout, stderr, timed_out) result."""
    try:
        p = subprocess.run(argv, timeout=timeout, **kw)
        return p.returncode, p.stdout or b"", p.stderr or b"", False
    except subprocess.TimeoutExpired as e:
        return None, e.stdout or b"", e.stderr or b"", True


def launch_shape(spec, rundir, env, argv, mode=None):
    """Launch the specimen once through one stdio shape.

    Returns (rc, stdout_bytes, stderr_bytes, timed_out, shape) where `rc` is
    always the SPECIMEN's own status in subprocess convention -- negative for
    death by signal -- for every shape that can determine it, and `shape` records
    everything about the connection as measured fact.
    """
    mode = mode or spec["stdio"]
    t = spec["timeout_s"]
    sd = _shape_dir(rundir)
    shape = {"mode": mode, "description": STDIO_SHAPES[mode],
             "status_source": "waitpid", "status_ambiguous": False}
    base = dict(cwd=rundir, env=env)

    if mode == "pipe":
        rc, so, se, to = _run(argv, t, input=spec["stdin"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, **base)
        return rc, so, se, to, shape

    if mode == "file":
        outp, errp = os.path.join(sd, "stdout.bin"), os.path.join(sd, "stderr.bin")
        with open(outp, "wb") as fo, open(errp, "wb") as fe:
            rc, _, _, to = _run(argv, t, input=spec["stdin"], stdout=fo, stderr=fe,
                                **base)
        so, se = _read_bytes(outp), _read_bytes(errp)
        shape.update({"stdout_file": outp, "stderr_file": errp,
                      "stdout_file_bytes": len(so),
                      "stdout_file_sha256": sha256_bytes(so),
                      "stderr_file_sha256": sha256_bytes(se)})
        return rc, so, se, to, shape

    if mode == "devnull-stdin":
        rc, so, se, to = _run(argv, t, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, **base)
        shape["stdin_path"] = os.devnull
        return rc, so, se, to, shape

    if mode == "file-stdin":
        inp = os.path.join(sd, "stdin.dat")
        with open(inp, "wb") as f:
            f.write(spec["stdin"])
        with open(inp, "rb") as f:
            rc, so, se, to = _run(argv, t, stdin=f, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, **base)
        shape.update({"stdin_path": inp, "stdin_file_bytes": len(spec["stdin"]),
                      "stdin_file_sha256": sha256_bytes(spec["stdin"])})
        return rc, so, se, to, shape

    if mode == "closed-stdout":
        # exec: the shell process BECOMES the specimen, so the wait status is the
        # specimen's own and there is no wrapper to confuse it with.
        wrapped = ["/bin/bash", "-c", 'exec "$@" >&-', "bash"] + argv
        rc, so, se, to = _run(wrapped, t, input=spec["stdin"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, **base)
        shape.update({"wrapper": " ".join(wrapped[:3]),
                      "status_source": "waitpid (bash exec'd the specimen, so no "
                                       "wrapper process survives to report its own "
                                       "status)"})
        return rc, so, se, to, shape

    if mode in ("tee", "cmdsub"):
        q = " ".join(shlex.quote(a) for a in argv)
        stp = os.path.join(sd, "specimen.status")
        if mode == "tee":
            teep = os.path.join(sd, "tee.bin")
            script = ("set -o pipefail; %s | tee -- %s; "
                      'printf %%s "${PIPESTATUS[0]}" > %s'
                      % (q, shlex.quote(teep), shlex.quote(stp)))
        else:
            script = ('out=$(%s); printf %%s "$?" > %s; printf %%s "$out"'
                      % (q, shlex.quote(stp)))
        rc_wrap, so, se, to = _run(["/bin/bash", "-c", script], t,
                                   input=spec["stdin"], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, **base)
        raw = _read_bytes(stp).decode("ascii", "replace").strip()
        spec_rc = int(raw) if raw.isdigit() else None
        shape.update({
            "wrapper_command": script,
            "wrapper_returncode": rc_wrap,
            "specimen_status_file": stp,
            "specimen_status_raw": raw,
            "status_source": "bash ${PIPESTATUS[0]}" if mode == "tee" else "bash $?",
            "status_ambiguous": spec_rc is not None and spec_rc >= 128,
        })
        if mode == "tee":
            tee_bytes = _read_bytes(teep)
            shape.update({"tee_file": teep, "tee_file_bytes": len(tee_bytes),
                          "tee_file_sha256": sha256_bytes(tee_bytes),
                          "tee_copy_matches_captured":
                              sha256_bytes(tee_bytes) == sha256_bytes(so)})
        else:
            shape["shell_stripped_trailing_newlines"] = None  # filled by the check
        return spec_rc, so, se, to, shape

    if mode == "earlyclose":
        limit = spec["stdio_limit"]
        if spec["stdin"]:
            # This shape hands the specimen /dev/null on stdin, because feeding a
            # pipe while deliberately refusing to drain stdout is a deadlock
            # waiting to happen. Declared input would be silently discarded, so
            # say so rather than losing it quietly.
            raise ValueError("the earlyclose shape does not deliver declared "
                             "stdin; %s declares %d bytes of it"
                             % (spec["id"], len(spec["stdin"])))
        errp = os.path.join(sd, "stderr.bin")
        rfd, wfd = os.pipe()
        got = b""
        rc, to = None, False
        # stderr goes to a FILE, not a pipe: this shape deliberately stops
        # draining stdout, and a second undrained pipe would deadlock on a
        # specimen whose oracle is longer than one pipe buffer.
        with open(errp, "wb") as fe:
            p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=wfd,
                                 stderr=fe, **base)
            os.close(wfd)
            try:
                while len(got) < limit:
                    chunk = os.read(rfd, min(65536, limit - len(got)))
                    if not chunk:
                        break
                    got += chunk
            finally:
                os.close(rfd)           # the consumer goes away, mid-stream
            try:
                rc = p.wait(timeout=t)
            except subprocess.TimeoutExpired:
                to = True
                p.kill()
                p.wait()
        se = _read_bytes(errp)
        shape.update({"consumer_read_limit": limit,
                      "stderr_file": errp,
                      "consumer_closed_after_bytes": len(got),
                      "consumer_reached_limit": len(got) >= limit})
        return rc, got, se, to, shape

    raise ValueError("unknown stdio shape %r" % (mode,))


def run_once(spec, out, rundir, binary, run_index):
    env = dict(BASE_ENV)
    env["HOME"] = os.path.join(rundir, "home")
    env["TMPDIR"] = os.path.join(rundir, "tmp")
    env["XDG_DATA_HOME"] = os.path.join(rundir, "xdg", "data")
    env["XDG_CONFIG_HOME"] = os.path.join(rundir, "xdg", "config")
    env["XDG_CACHE_HOME"] = os.path.join(rundir, "xdg", "cache")
    for d in ("home", "tmp", "xdg/data", "xdg/config", "xdg/cache"):
        os.makedirs(os.path.join(rundir, *d.split("/")), exist_ok=True)
    env["FIXTURE_ID"] = spec["id"]
    if spec["stage"] in ("ldpath", "dlopen"):
        env["LD_LIBRARY_PATH"] = os.path.join(out, "lib")
    mapping = {"LIBDIR": os.path.join(out, "lib"),
               "BINDIR": os.path.join(out, "bin"),
               "HELPER": os.path.join(out, "bin", "helper_child")}
    # Environment VALUES are substituted too, so a specimen can be told to find
    # something on PATH without the corpus root being baked into the table.
    env.update({k: subst([v], mapping)[0] for k, v in spec["env"].items()})
    argv = [binary] + subst(spec["argv"], mapping)

    display_run = None
    if spec.get("display") == "private":
        helper = os.path.join(out, "run_on_private_display.sh")
        num = next_display()
        inner = list(argv)
        hold = spec.get("display_hold_s") or 0
        until = spec.get("display_hold_until")
        if hold:
            # A real X server does not die when one application exits. This one
            # does: pd_run kills Xvfb the instant the command it launched
            # returns, so a child left running loses its display and then its
            # namespace. Holding the STAGE open after the launched process exits
            # is the harness providing what a desktop provides; it belongs to the
            # wrapper and not to the specimen, whose own process still exits
            # first. Without it, a GUI-orphan specimen measures the harness
            # rather than the program.
            #
            # `until` rather than a fixed sleep, because a fixed margin is a race
            # and not a fix: eight seconds was enough on a quiet host and not
            # enough when twelve other specimens were running, so the fixture
            # failed for a reason that had nothing to do with its property.
            # Waiting for the artifact to APPEAR removes the race; `hold` is only
            # the ceiling. This does not weaken anything -- the declaration is
            # still that the file exists and contains the declared lines, and if
            # the orphan never writes it, the wait expires and the specimen
            # fails exactly as it should.
            if until:
                script = ('"$@"; rc=$?; '
                          'for _ in $(seq 1 %d); do [ -e %s ] && break; '
                          'sleep 0.1; done; sleep 0.3; exit $rc'
                          % (int(hold * 10), shlex.quote(until)))
            else:
                script = '"$@"; rc=$?; sleep %g; exit $rc' % hold
            inner = ["/bin/bash", "-c", script, "bash"] + inner
        argv = [helper, str(num)] + inner
        env.pop("DISPLAY", None)       # pd_run sets it inside the namespace
        env.pop("WAYLAND_DISPLAY", None)
        display_run = {
            "mode": "private",
            "display_number": num,
            "helper": helper,
            "library": PD_LIB,
            "stage_hold_ceiling_seconds": hold,
            "stage_held_until_file_appears": until,
            "status_source":
                "the private-display wrapper is unshare plus bash, so a specimen "
                "killed by signal n is reported as EXIT 128+n and cannot be "
                "distinguished from a specimen that exited 128+n. A specimen "
                "here therefore declares an exit code, never a signal; the "
                "console crash specimens are what prove signal death is "
                "observable at all.",
        }
    elif spec.get("display") == "none":
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
        display_run = {"mode": "none",
                       "status_source": "waitpid",
                       "note": "DISPLAY and WAYLAND_DISPLAY removed outright"}

    # A reference capture through a plain pipe, for the shapes that TRANSFORM the
    # stream. Without it, "the shell stripped the trailing newline" would be an
    # assumption about bash rather than a measured difference between two
    # captures of the same program.
    ref = None
    if spec.get("stdio_reference") and spec["stdio"] != "pipe":
        _, ref, _, _, _ = launch_shape(spec, rundir, env, argv, mode="pipe")

    t0 = time.time()
    rc, so, se, timed_out, shape = launch_shape(spec, rundir, env, argv)
    dur = round((time.time() - t0) * 1000.0, 1)
    if ref is not None:
        shape.update({"reference_mode": "pipe",
                      "reference_stdout_bytes": len(ref),
                      "reference_stdout_sha256": sha256_bytes(ref),
                      "captured_equals_reference": so == ref,
                      "captured_is_prefix_of_reference": ref.startswith(so),
                      "captured_equals_reference_rstrip_newlines":
                          so == ref.rstrip(b"\n"),
                      "captured_equals_reference_nuls_removed_rstrip_newlines":
                          so == ref.replace(b"\x00", b"").rstrip(b"\n"),
                      "trailing_newlines_lost":
                          len(ref) - len(ref.rstrip(b"\n")) if so == ref.rstrip(b"\n")
                          else None})
    stream = se if spec["declared"]["oracle_stream"] == "stderr" else so
    kv, order, det, repeats = parse_oracle(stream.decode("utf-8", "replace"))
    return {
        "run_index": run_index,
        "argv": argv,
        "env_extra": {k: v for k, v in env.items() if k not in BASE_ENV},
        "exit_code": rc if (rc is None or rc >= 0) else None,
        "signal": (-rc) if (rc is not None and rc < 0) else None,
        "signal_name": next((n for n, v in SIGNAMES.items() if rc is not None and rc == -v),
                            None),
        "timed_out": timed_out,
        "duration_ms": dur,
        "stdout_bytes": len(so),
        "stderr_bytes": len(se),
        "stdout_sha256": sha256_bytes(so),
        "stderr_sha256": sha256_bytes(se),
        # FNV-1a is a byte-at-a-time Python loop: about half a second per MiB.
        # It was free when the largest stream in the corpus was 8 MiB and it is
        # minutes per run at 256 MiB, so it is computed only up to the size that
        # already had one. Nothing is lost: stdout_sha256 above covers the same
        # stream at C speed, and every bulk specimen attests to its own SHA-256.
        "stdout_fnv1a64": ("%016x" % fnv1a64(so)
                           if len(so) <= FNV_STREAM_LIMIT else None),
        "stdout_fnv1a64_skipped_over_limit": len(so) > FNV_STREAM_LIMIT,
        "oracle": kv,
        "oracle_repeated_keys": sorted(set(repeats)),
        "oracle_deterministic_lines": det,
        "observations": {k[4:]: v for k, v in kv.items() if k.startswith("OBS_")},
        "stdout_head": so[:2048].decode("utf-8", "replace"),
        "stderr_head": se[:2048].decode("utf-8", "replace"),
        "stdio_shape": shape,
        "display_run": display_run,
        "display_status_ambiguous": bool(
            display_run and display_run["mode"] == "private"
            and rc is not None and 128 < rc < 160),
        "_stdout": so,
        "_stderr": se,
    }


def stage_run_dir(spec, out):
    rundir = os.path.join(out, "run", spec["id"])
    if os.path.exists(rundir):
        shutil.rmtree(rundir)
    os.makedirs(rundir)
    for rel, content in spec["staged_files"].items():
        path = os.path.join(rundir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    return rundir

# --------------------------------------------------------------------------
# Verdict: does the specimen behave the way it was declared to?
# --------------------------------------------------------------------------

def check_elf(declared, actual):
    problems = []
    for key, want in declared.items():
        if key == "needed_contains":
            for lib in want:
                if not any(lib in n for n in actual.get("needed", [])):
                    problems.append("NEEDED is missing %s (has %s)"
                                    % (lib, actual.get("needed")))
        elif key == "needed_excludes":
            for lib in want:
                if any(lib in n for n in actual.get("needed", [])):
                    problems.append("NEEDED unexpectedly contains %s" % lib)
        elif key == "rpath_set":
            if bool(actual.get("rpath")) != bool(want):
                problems.append("rpath_set expected %s, got %r" % (want, actual.get("rpath")))
        elif key == "runpath_set":
            if bool(actual.get("runpath")) != bool(want):
                problems.append("runpath_set expected %s, got %r"
                                % (want, actual.get("runpath")))
        else:
            got = actual.get(key, "<absent>")
            if got != want:
                problems.append("elf.%s expected %r, got %r" % (key, want, got))
    return problems


def _stream_bytes(last, name):
    return last["_stdout"] if name == "stdout" else last["_stderr"]


def check_bulk(bulk, last):
    """Verify a specimen's own attestation about a bulk stream against the bytes
    the runner actually captured.

    `fnv_key` is the original form and still works. `sha_key` was added because
    FNV-1a has to be recomputed a byte at a time in Python -- a few seconds at
    8 MiB, minutes at 256 MiB -- while hashlib computes SHA-256 at C speed, and
    the index already records a SHA-256 of every captured stream, so the
    specimen's claim and the runner's observation are directly comparable. A
    specimen may attest with either or both; only the keys it declares are
    checked.

    `also` exists for the one specimen where BOTH streams are bulk and there is
    therefore no spare stream to report on. Its oracle is appended to stderr
    after the payload, so what is checkable is a SLICE of that stream.

    The slice is located by a FRAME and never by a byte offset. The first version
    took `offset_key`, an absolute byte position the specimen reported -- and that
    position counts the header lines before the payload, one of which is
    `FIXTURE_ID=<id>` whose value comes from the environment. Clear the
    environment and the id falls back to a shorter literal, the header shrinks,
    and the "deterministic" offset moves by the difference in id length. Located
    by a delimiter instead, nothing about finding the payload depends on the
    environment, the id, or the length of any header line.
    """
    problems = []
    oracle = last["oracle"]
    raw = _stream_bytes(last, bulk["stream"])
    if bulk.get("bytes_key"):
        want_len = oracle.get(bulk["bytes_key"])
        if want_len is None or int(want_len) != len(raw):
            problems.append("%s stream is %d bytes, specimen claimed %r"
                            % (bulk["stream"], len(raw), want_len))
    if bulk.get("fnv_key"):
        want_fnv = oracle.get(bulk["fnv_key"])
        got_fnv = "%016x" % fnv1a64(raw)
        if want_fnv != got_fnv:
            problems.append("%s FNV-1a: specimen claimed %r, runner computed %s"
                            % (bulk["stream"], want_fnv, got_fnv))
    if bulk.get("sha_key"):
        want_sha = oracle.get(bulk["sha_key"])
        got_sha = sha256_bytes(raw)
        if want_sha != got_sha:
            problems.append("%s SHA-256: specimen claimed %r, runner computed %s"
                            % (bulk["stream"], want_sha, got_sha))
    for extra in bulk.get("also", []):
        stream = _stream_bytes(last, extra["stream"])
        delim = oracle.get(extra["delimiter_key"])
        length = oracle.get(extra["bytes_key"])
        if delim is None or length is None:
            problems.append("%s slice: specimen did not report %s and %s"
                            % (extra["stream"], extra["delimiter_key"],
                               extra["bytes_key"]))
            continue
        # Anchored on newlines at both ends, so the line that ANNOUNCES the
        # delimiter is not a false match: it is preceded by '=', not by '\n'.
        frame = b"\n" + delim.encode() + b"\n"
        first = stream.find(frame)
        second = stream.find(frame, first + 1) if first >= 0 else -1
        third = stream.find(frame, second + 1) if second >= 0 else -1
        if first < 0 or second < 0:
            problems.append("%s: found %d of the 2 expected %r frame markers"
                            % (extra["stream"], (first >= 0) + (second >= 0), delim))
            continue
        if third >= 0:
            problems.append("%s: found more than 2 %r frame markers, so the "
                            "payload boundary is ambiguous" % (extra["stream"], delim))
            continue
        payload = stream[first + len(frame):second]
        if len(payload) != int(length):
            problems.append("%s framed payload is %d bytes, specimen claimed %r"
                            % (extra["stream"], len(payload), length))
            continue
        want_sha = oracle.get(extra["sha_key"])
        got_sha = sha256_bytes(payload)
        if want_sha != got_sha:
            problems.append("%s framed payload SHA-256 over [%d:%d]: specimen "
                            "claimed %r, runner computed %s"
                            % (extra["stream"], first + len(frame), second,
                               want_sha, got_sha))
    return problems


def check_stdio(spec, last):
    """Check the declared facts about the CONNECTION, not about the program.

    Every key here is a relation between two things that were both measured --
    the tee'd copy and the captured copy, the captured stream and a reference
    capture of the same program through a plain pipe. None of them is a byte
    offset into a stream, and none is a length taken as an identity: a length
    cannot tell a truncated stream from a reordered one, and a stream that also
    carries FIXTURE_ID has a length that depends on the environment.
    """
    problems = []
    want = spec["declared"].get("stdio_expect") or {}
    shape = last.get("stdio_shape") or {}
    if shape.get("mode") != spec["stdio"]:
        problems.append("stdio shape recorded as %r, spec declares %r"
                        % (shape.get("mode"), spec["stdio"]))
    if spec["stdio"] in SHELL_STATUS_SHAPES and shape.get("status_ambiguous"):
        problems.append("the %s shape reported status %r through bash, which "
                        "cannot distinguish an exit code of 128+n from death by "
                        "signal n; this shape must only be used for specimens "
                        "declared to exit normally below 128"
                        % (spec["stdio"], shape.get("specimen_status_raw")))
    for key, expected in want.items():
        if key not in shape:
            problems.append("stdio_expect names %s, which the %s shape does not "
                            "record" % (key, spec["stdio"]))
            continue
        got = shape[key]
        if got != expected:
            problems.append("stdio %s: declared %r, measured %r"
                            % (key, expected, got))
    return problems


def verdict_for(spec, runs, post_state):
    d = spec["declared"]
    problems = []
    last = runs[-1]

    if last["timed_out"]:
        problems.append("timed out after %.0fs" % spec["timeout_s"])

    if d["signal"] is not None:
        want = SIGNAMES[d["signal"]]
        if last["signal"] != want:
            problems.append("declared death by %s (%d), observed signal=%r exit=%r"
                            % (d["signal"], want, last["signal"], last["exit_code"]))
        if "RESULT" in last["oracle"]:
            problems.append("declared death, but a RESULT line was printed")
    else:
        if last["signal"] is not None:
            problems.append("died from signal %s, none declared" % last["signal_name"])
        if last["exit_code"] != d["exit_code"]:
            problems.append("exit code: declared %r, observed %r"
                            % (d["exit_code"], last["exit_code"]))
        result = last["oracle"].get("RESULT")
        if d.get("requires_result_pass", True) and result != "PASS":
            problems.append("RESULT line is %r, expected PASS (the specimen's own "
                            "self-checks failed or it did not finish)" % result)

    for key, want in d["expect"].items():
        got = last["oracle"].get(key, "<absent>")
        if want is None:
            if key not in last["oracle"]:
                problems.append("declared key %s is absent" % key)
        elif got != want:
            problems.append("%s: declared %r, observed %r" % (key, want, got))

    for pair in d.get("equal_keys", []):
        a, b = pair
        va, vb = last["oracle"].get(a), last["oracle"].get(b)
        if va is None or vb is None or va != vb:
            problems.append("%s and %s must be equal (got %r and %r)" % (a, b, va, vb))

    for key, seq in d.get("expect_sequence", {}).items():
        got = [r["oracle"].get(key) for r in runs]
        if got != seq:
            problems.append("%s across runs: declared %r, observed %r" % (key, seq, got))

    bulk = d.get("bulk_check")
    if bulk:
        problems += check_bulk(bulk, last)

    problems += check_stdio(spec, last)

    # A private-display specimen cannot declare death by signal: the wrapper is
    # a shell chain and flattens it to exit 128+n. Refusing the declaration is
    # the honest response -- accepting 139 AS SIGSEGV would be the generator
    # quietly inventing a distinction the measurement cannot make.
    if spec.get("display") == "private" and d["signal"] is not None:
        problems.append(
            "declared death by %s, but this specimen runs on the private "
            "display, where the wrapper reports a signal as exit 128+n and "
            "nothing can tell that apart from an exit code of 128+n. Declare "
            "the exit code and say why, or run the crash on the console."
            % d["signal"])

    for name, needles in d["post_files"].items():
        content = post_state.get(name)
        if content is None:
            problems.append("declared post-run file %s was never created" % name)
            continue
        for needle in needles:
            if needle not in content:
                problems.append("post-run file %s lacks %r" % (name, needle))
    return problems


def collect_post(spec, rundir):
    state = {}
    for name in spec["declared"]["post_files"]:
        path = os.path.join(rundir, name)
        if os.path.exists(path):
            with open(path, "r", errors="replace") as f:
                state[name] = f.read()
    return state

# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def process(spec, out):
    rec = {k: v for k, v in spec.items() if k != "stdin"}
    rec["stdin"] = {"bytes": len(spec["stdin"]),
                    "sha256": sha256_bytes(spec["stdin"]) if spec["stdin"] else None}
    rec["source"] = {
        "files": spec["sources"],
        "sha256": {s: sha256_file(os.path.join(SPECS, s)) for s in spec["sources"]},
        "oracle_header_sha256": sha256_file(os.path.join(SPECS, "oracle.h")),
    }
    build = build_one(spec, out)
    build["compiler_version"] = TOOL_VERSIONS.get(build["compiler"], "?")
    rec["build"] = build
    if not build["ok"]:
        rec["verdict"] = {"status": "build-failed",
                          "problems": [build["warnings"][-1500:] or "compiler failed"]}
        rec["binary"] = None
        rec["baseline"] = None
        return rec

    target = build["target"]
    actual_elf = elf_facts(target)
    elf_problems = check_elf(spec["declared"]["elf"], actual_elf)

    # Compiler diagnostics are a declared property, not an incidental field.
    want_warn = spec["declared"].get("build_warning_contains")
    got_warn = build.get("warnings") or ""
    if want_warn is None:
        if got_warn:
            elf_problems.append(
                "the build emitted diagnostics and none were declared: %r. A "
                "specimen that warns is either wrong or interesting; say which "
                "with expect_build_warning=." % got_warn[:300])
    elif want_warn not in got_warn:
        elf_problems.append("declared a build diagnostic containing %r; the "
                            "build said %r" % (want_warn, got_warn[:300]))
    rec["binary"] = {
        "path": target,
        "sha256": sha256_file(target),
        "size_bytes": os.path.getsize(target),
        "elf": actual_elf,
        "declared_elf_problems": elf_problems,
    }

    rundir = stage_run_dir(spec, out)
    runs = []
    for i in range(spec["runs"]):
        runs.append(run_once(spec, out, rundir, target, i))
    if spec["settle_s"]:
        time.sleep(spec["settle_s"])
    post = collect_post(spec, rundir)
    problems = elf_problems + verdict_for(spec, runs, post)
    for r in runs:
        r.pop("_stdout", None)
        r.pop("_stderr", None)
    rec["baseline"] = {
        "run_dir": rundir,
        "runs": runs,
        "post_run_files": post,
        "run_dir_listing": sorted(os.listdir(rundir)),
    }
    rec["verdict"] = {"status": "baseline-ok" if not problems else "baseline-mismatch",
                      "problems": problems}
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/lexe-workloads")
    ap.add_argument("--only", default=None, help="substring filter on fixture id")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 4) // 2))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)

    global TOOL_VERSIONS
    TOOL_VERSIONS = {}
    missing = []
    for name, tc in TOOLCHAINS.items():
        for key in ("cc", "cxx"):
            binary = tc[key]
            if binary in TOOL_VERSIONS:
                continue
            if shutil.which(binary) is None:
                missing.append(binary)
                TOOL_VERSIONS[binary] = "ABSENT"
            else:
                TOOL_VERSIONS[binary] = tool_version(binary)

    t0 = time.time()
    libs = build_libs(out)
    display_helper = write_display_helper(out)
    helper = build_helper(out)

    chosen = [s for s in SPECIMENS if not args.only or args.only in s["id"]]
    results = []
    with futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {pool.submit(process, s, out): s for s in chosen}
        for fut in futures.as_completed(futs):
            spec = futs[fut]
            try:
                rec = fut.result()
            except Exception as exc:  # a generator bug must not look like a specimen bug
                rec = {"id": spec["id"], "verdict": {"status": "generator-error",
                                                     "problems": [repr(exc)]}}
            results.append(rec)
            if not args.quiet:
                v = rec.get("verdict", {})
                print("%-14s %s" % (v.get("status", "?"), rec["id"]))
                for p in v.get("problems", [])[:6]:
                    print("               ! %s" % p)
    results.sort(key=lambda r: r["id"])
    elapsed = round(time.time() - t0, 1)

    # A compiler differential is only evidence if it agrees with its base on
    # every deterministic line. Where it does not, either the source has
    # undefined behaviour or a toolchain is wrong; either way it is reported.
    by_rid = {r["id"]: r for r in results}
    divergences = []
    for r in results:
        base = by_rid.get(r.get("differential_of"))
        if not base or not r.get("baseline") or not base.get("baseline"):
            continue

        def det(rec):
            return [ln for ln in rec["baseline"]["runs"][-1]["oracle_deterministic_lines"]
                    if not ln.startswith("FIXTURE_ID=")]

        a, b = det(base), det(r)
        only_base = [ln for ln in a if ln not in b]
        only_diff = [ln for ln in b if ln not in a]
        agrees = not (only_base or only_diff)
        r["differential_agreement"] = {
            "base": base["id"], "agrees": agrees,
            "only_in_base": only_base[:20], "only_in_differential": only_diff[:20],
        }
        if not agrees:
            divergences.append(r["id"])
    if divergences:
        print("DIFFERENTIAL DIVERGENCE in %d specimen(s): %s"
              % (len(divergences), ", ".join(divergences)))

    counts = {}
    for r in results:
        counts[r["verdict"]["status"]] = counts.get(r["verdict"]["status"], 0) + 1
    index = {
        "schema": "lexe.workload.index/1",
        "schema_notes": {
            "declared": "written by hand before the specimen was ever run; the "
                        "generator checks the observation against it",
            "baseline": "what direct execution actually did, recorded as the "
                        "reference for any later indirect execution",
            "oracle_deterministic_lines": "every oracle line whose key does not "
                                          "start with OBS_; compare these exactly",
            "observations": "OBS_ values: environment-dependent, never a failure "
                            "on their own",
            "verdict.status": "baseline-ok means the specimen is admitted to the "
                              "corpus; baseline-mismatch means the FIXTURE is "
                              "wrong and must not be used as evidence",
        },
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generator": {"file": os.path.basename(__file__),
                      "sha256": sha256_file(os.path.abspath(__file__)),
                      "specs_dir": SPECS,
                      "wall_seconds": elapsed,
                      "jobs": args.jobs},
        "host": host_facts(),
        "toolchains": {k: {"cc": v["cc"], "cxx": v["cxx"], "opt": v["opt"],
                           "cc_version": TOOL_VERSIONS.get(v["cc"]),
                           "cxx_version": TOOL_VERSIONS.get(v["cxx"]),
                           "common_c_flags": COMMON_C, "common_cxx_flags": COMMON_CXX}
                       for k, v in TOOLCHAINS.items()},
        "absent_toolchains": sorted(set(missing)),
        "corpus_root": out,
        "support_libraries": libs,
        # How the GUI specimens got a display, and the sha256 of the script that
        # provided it: the isolation is part of the definition of those runs, so
        # it belongs in the manifest rather than in a comment.
        "private_display": display_helper,
        "stdio_shapes": STDIO_SHAPES,
        "helper_binary": helper,
        "counts": {"specimens": len(results),
                   "differential_specimens": sum(1 for r in results
                                                 if r.get("differential_of")),
                   "differential_divergences": len(divergences), **counts},
        "differential_divergences": divergences,
        "families": sorted({r.get("family", "?") for r in results}),
        "specimens": results,
    }
    index_path = os.path.join(out, "index.json")
    with open(index_path, "w") as f:
        json.dump(index, f, indent=1, sort_keys=False)
    print("\n%d specimens, %s, %.1fs -> %s"
          % (len(results), ", ".join("%s=%d" % kv for kv in sorted(counts.items())),
             elapsed, index_path))
    return 0 if counts.get("baseline-ok", 0) == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())

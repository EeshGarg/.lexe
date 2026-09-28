#!/usr/bin/env python3
"""Windows PE workload factory for .LEXE.

Builds a corpus of small, deterministic, intentionally unusual Windows programs,
records a DIRECT baseline for each one UNDER EACH TRANSLATION LAYER SEPARATELY,
and emits a machine-readable index.

Why per-layer baselines: a difference between Wine and Proton is not the same
fact as a difference caused by .LEXE, and the two must never be conflated. The
index therefore gives a consumer up to four cells per specimen --

    native      the same source built as a Linux ELF, where the source is
                portable enough for that to mean anything (the reference)
    wine        the system Wine, directly
    proton-run  Proton's own `proton run` entry point, directly
    proton-wine the Wine binary shipped inside Proton, directly

-- before .LEXE is involved at all. Where two layers disagree, that difference is
recorded as a property of the layers.

One measured fact shapes the whole design: under `proton run` the guest program's
stdout and stderr are NOT delivered to the caller, while its exit code and its
file side effects are. Every specimen therefore writes its oracle to a FILE as
well as to the stream (see specs_pe/oracle_win.h), and the file is the primary
comparison artifact.

Usage (inside WSL):
    python3 generate_pe.py [--out DIR] [--only SUBSTR] [--repeats N]
                           [--layers wine,proton-run,...] [--jobs N]

Build products land in --out (default /tmp/lexe-workloads-pe), never in the repo.
"""

import argparse
import concurrent.futures as futures
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

BS = chr(92)  # a literal backslash, spelled this way to survive every layer of
              # quoting between here and a Windows registry key.

HERE = os.path.dirname(os.path.abspath(__file__))
SPECS = os.path.join(HERE, "specs_pe")
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PD_LIB = os.path.join(REPO, "scripts", "lib", "private-display.sh")

PROTON_DIR = os.path.expanduser(
    "~/.steam/root/compatibilitytools.d/GE-Proton11-7-x86_64")
PROTON_SCRIPT = os.path.join(PROTON_DIR, "proton")
PROTON_WINE = os.path.join(PROTON_DIR, "files", "bin", "wine")
STEAM_CLIENT = os.path.expanduser("~/.steam/steam")

# Reproducible links: without this, two builds of the same source differ in
# exactly two bytes (the PE TimeDateStamp), which makes the corpus
# unverifiable for no benefit. Verified under gcc x86-64, gcc i686 and
# clang --target=x86_64-w64-mingw32.
LINK_REPRODUCIBLE = ["-Wl,--no-insert-timestamp"]

COMMON_C = ["-std=gnu11", "-Wall", "-Wextra", "-I" + SPECS]
COMMON_CXX = ["-std=gnu++17", "-Wall", "-Wextra", "-I" + SPECS]

TOOLCHAINS = {
    "mingw64-O2": {"cc": "x86_64-w64-mingw32-gcc", "cxx": "x86_64-w64-mingw32-g++",
                   "opt": ["-O2"], "target": "x86_64", "extra": []},
    "mingw64-O0": {"cc": "x86_64-w64-mingw32-gcc", "cxx": "x86_64-w64-mingw32-g++",
                   "opt": ["-O0", "-g"], "target": "x86_64", "extra": []},
    "mingw32-O2": {"cc": "i686-w64-mingw32-gcc", "cxx": "i686-w64-mingw32-g++",
                   "opt": ["-O2"], "target": "i686", "extra": []},
    "clang-mingw64-O2": {"cc": "clang", "cxx": "clang++", "opt": ["-O2"],
                         "target": "x86_64",
                         "extra": ["--target=x86_64-w64-mingw32"]},
}

ALL_LAYERS = ["native", "wine", "proton-run", "proton-wine"]

DEFAULT_LAYERS_NOTE = (
    "proton-run -- Proton's own `python3 proton run` entry point -- is implemented "
    "here but is NOT in the default layer list, because on this host it cannot be "
    "baselined at all. Measured, in this order: it delivers none of the guest's "
    "stdout or stderr; it never returns unless DISPLAY names a working X server; a "
    "guest that reads stdin blocks forever even with stdin at /dev/null; two "
    "concurrent invocations against one prefix intermittently fail to start the "
    "guest; and whenever an invocation is interrupted -- including by its own "
    "timeout, with no mount namespace anywhere in sight -- it leaves processes in "
    "uninterruptible D state waiting on a FUSE connection that nothing will ever "
    "answer. Those processes cannot be killed, they poison that Proton prefix for "
    "every later run, and the only way to clear them is to restart the WSL distro. "
    "A layer that cannot be baselined is not a baseline, so Proton coverage in this "
    "corpus is carried by proton-wine: Proton's OWN Wine binary and prefix, run "
    "directly, which is stable, headless, parallel-safe and fully baselined.")

# Layers where the guest program's own stdout/stderr reach the caller. Under
# `proton run` they do not: measured, not assumed.
LAYERS_WITH_STDIO = {"native", "wine", "proton-wine"}


def _as_text(x):
    """subprocess hands back BYTES in a TimeoutExpired even when text=True was
    asked for. Concatenating a message onto that raises TypeError and killed a
    whole generation once, from inside the error path of a timeout -- so the
    coercion is explicit here rather than assumed."""
    if x is None:
        return ""
    if isinstance(x, bytes):
        return x.decode("utf-8", "replace")
    return x


def sh(cmd, timeout=300, **kw):
    """Run a command and never wait forever. A hung toolchain or a hung
    translation layer is a finding, not something to sit through."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, **kw)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(
            cmd, 124, _as_text(e.stdout),
            _as_text(e.stderr) + chr(10)
            + "[generator] timed out after " + str(timeout) + "s")


def sh_detached(cmd, **kw):
    """Start a command that DAEMONISES and keeps running -- `wineserver -p` is
    the only user. It must not be run through sh(): capture_output gives it pipes,
    the daemon inherits them and never closes them, and subprocess.run() waits for
    EOF rather than for the process, so a 60-second timeout fires on a command
    that in fact succeeded in milliseconds. (The same trap as finding 13 in
    README-PE.md, met from the other side.)"""
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60, **kw)
        return p.returncode
    except subprocess.TimeoutExpired:
        return 124


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
    if shutil.which(binary) is None:
        return "ABSENT"
    r = sh([binary, "--version"])
    text = (r.stdout or r.stderr or "").splitlines()
    return text[0].strip() if text else "unknown"


def host_facts():
    return {
        "uname": sh(["uname", "-srvmo"]).stdout.strip(),
        "distro": next((l.split("=", 1)[1].strip().strip('"')
                        for l in open("/etc/os-release") if l.startswith("PRETTY_NAME=")), "?"),
        "nproc": int(sh(["nproc"]).stdout.strip() or 1),
        "wine_version": tool_version("wine"),
        "proton_version": (open(os.path.join(PROTON_DIR, "version")).read().strip()
                           if os.path.exists(os.path.join(PROTON_DIR, "version")) else "ABSENT"),
        "proton_dir": PROTON_DIR,
        "xvfb": tool_version("Xvfb"),
        "preexisting_wine_processes": len([
            l for l in sh(["ps", "-eo", "comm="]).stdout.split(chr(10))
            if l.strip().endswith(".exe") or l.strip() == "wineserver"]),
    }


def pe_facts(path):
    """What the built file actually is, read out of the PE headers rather than
    assumed from the compiler flags."""
    out = {}
    f = sh(["file", "-b", path])
    out["file_says"] = f.stdout.strip()
    p = sh(["x86_64-w64-mingw32-objdump", "-p", path])
    if p.returncode != 0:
        out["objdump_failed"] = p.stderr.strip()[:200]
        return out
    text = p.stdout
    m = re.search(r"^Magic\s+(\S+)", text, re.M)
    out["pe_magic"] = m.group(1) if m else "?"
    out["pe_format"] = ("PE32+" if out.get("pe_magic") == "020b"
                        else "PE32" if out.get("pe_magic") == "010b" else "?")
    m = re.search(r"^Subsystem\s+\S+\s+\((.+)\)", text, re.M)
    out["subsystem"] = m.group(1).strip() if m else "?"
    out["subsystem_is_gui"] = "GUI" in out.get("subsystem", "")
    out["subsystem_is_console"] = "CUI" in out.get("subsystem", "")
    out["imported_dlls"] = sorted(set(re.findall(r"^\tDLL Name: (\S+)", text, re.M)))
    m = re.search(r"^ImageBase\s+(\S+)", text, re.M)
    out["image_base"] = m.group(1) if m else "?"
    m = re.search(r"DllCharacteristics\s+(\S+)", text)
    out["dll_characteristics"] = m.group(1) if m else None
    a = sh(["x86_64-w64-mingw32-objdump", "-f", path])
    m = re.search(r"architecture: (\S+),", a.stdout)
    out["architecture"] = m.group(1).rstrip(",") if m else "?"
    out["machine_is_x86_64"] = out.get("architecture", "").startswith("i386:x86-64")
    t = sh(["x86_64-w64-mingw32-objdump", "-t", path])
    # A stripped PE has no symbol table for objdump to print.
    out["has_symbol_table"] = "no symbols" not in t.stdout.lower()
    s = sh(["x86_64-w64-mingw32-objdump", "-h", path])
    out["has_debug_section"] = ".debug_info" in s.stdout
    out["stripped"] = not out["has_symbol_table"]
    return out


def check_pe(declared, actual):
    problems = []
    for key, want in declared.items():
        if key == "imports_contains":
            for dll in want:
                if not any(dll.lower() in d.lower() for d in actual.get("imported_dlls", [])):
                    problems.append("imports are missing %s (has %s)"
                                    % (dll, actual.get("imported_dlls")))
        elif key == "imports_excludes":
            for dll in want:
                if any(dll.lower() in d.lower() for d in actual.get("imported_dlls", [])):
                    problems.append("imports unexpectedly contain %s" % dll)
        else:
            got = actual.get(key, "<absent>")
            if got != want:
                problems.append("pe.%s expected %r, got %r" % (key, want, got))
    return problems


# --------------------------------------------------------------------------
# The specimen table. Every field is a DECLARATION written before the specimen
# was ever run.
#
#   layers          which of the four cells this specimen is declared for
#   expect          KEY -> exact value required in the oracle FILE, every layer
#   expect_by_layer per-layer overrides, for properties that legitimately differ
#   expect_one_of   KEY -> list of acceptable values, for a property whose
#                   outcome is a platform choice rather than a program choice
#   pe              properties the built file must actually have (read with
#                   objdump), so "I passed -mwindows" is never taken on trust
#   gui             run on a private X server; never on a real desktop
# --------------------------------------------------------------------------

SPECIMENS = []
# `dir` puts a DLL in a subdirectory of out/dll. wsearch.dll is built TWICE, with
# the SAME FILE NAME and different contents, into two different directories: that
# is the only way a specimen can say WHICH of them the loader found, and therefore
# the only way to observe DLL search order rather than merely DLL loading.
DLLS = [
    {"name": "wlib.dll", "src": "wlib.c", "toolchain": "mingw64-O2", "implib": "libwlib.a"},
    {"name": "wlib32.dll", "src": "wlib.c", "toolchain": "mingw32-O2", "implib": None},
    {"name": "wsearch.dll", "src": "wsearch.c", "toolchain": "mingw64-O2", "implib": None,
     "dir": "search-primary",
     "cflags": ["-DWSEARCH_WHICH=primary", "-DWSEARCH_VALUE=1111"]},
    {"name": "wsearch.dll", "src": "wsearch.c", "toolchain": "mingw64-O2", "implib": None,
     "dir": "search-alt",
     "cflags": ["-DWSEARCH_WHICH=alt", "-DWSEARCH_VALUE=2222"]},
]


def S(fid, src, family, prop, **kw):
    spec = {
        "id": fid,
        "family": family,
        "property": prop,
        "sources": src if isinstance(src, list) else [src],
        "toolchain": kw.get("tc", "mingw64-O2"),
        "language": "c++" if str(src).endswith(".cpp") else "c",
        "cflags": list(kw.get("cflags", [])),
        "stage": kw.get("stage", "plain"),
        "argv": list(kw.get("argv", [])),
        "env": dict(kw.get("env", {})),
        "stdin": kw.get("stdin", b""),
        "gui": kw.get("gui", False),
        "layers": list(kw.get("layers", ["wine", "proton-run", "proton-wine"])),
        "oracle_file": kw.get("oracle_file"),
        "declared": {
            "exit_code": kw.get("exit", 0),
            "exit_code_by_layer": dict(kw.get("exit_by_layer", {})),
            "nonzero_exit_required": kw.get("nonzero_exit", False),
            "expect": dict(kw.get("expect", {})),
            "expect_by_layer": dict(kw.get("expect_by_layer", {})),
            "expect_one_of": dict(kw.get("expect_one_of", {})),
            "expect_absent": list(kw.get("expect_absent", [])),
            "requires_result_pass": kw.get("result", True),
            "timeout_allowed": kw.get("timeout_allowed", False),
            "exit_one_of_by_layer": dict(kw.get("exit_one_of_by_layer", {})),
            "instability_expected": kw.get("instability_expected", None),
            "warmup_launch": kw.get("warmup", False),
            "post_files": dict(kw.get("post", {})),
            # What FIXTURE_BUILD_ID must say. The fixture id for an ordinary
            # specimen, which is built for that fixture alone; the NODE name for
            # a process-tree specimen, whose binaries are built once and shared
            # by every mode and can therefore only identify themselves.
            "build_id_expected": kw.get("build_id_expected", fid),
            # {filename: terminal line}. Turns settle_s from a fixed sleep --
            # which is a race -- into a condition with settle_s as its ceiling.
            "post_files_complete_when": dict(kw.get("post_complete_when", {})),
            "duration_class": kw.get("duration", "sub-second"),
            "capabilities": list(kw.get("caps", [])),
            "filesystem_effects": list(kw.get("effects", [])),
            "process_behaviour": kw.get("procbeh", "single-process"),
            "pe": dict(kw.get("pe", {})),
        },
        "staged_files": dict(kw.get("files", {})),
        "settle_s": kw.get("settle", 0.0),
        "runs": kw.get("runs", 1),
        "timeout_s": kw.get("timeout", 120.0),
        "notes": kw.get("notes", ""),
    }
    SPECIMENS.append(spec)
    return spec


PE64 = {"pe_format": "PE32+", "machine_is_x86_64": True, "subsystem_is_console": True}
CUI = {"subsystem_is_console": True, "subsystem_is_gui": False}

# ---- format and toolchain ------------------------------------------------
S("pe-format-console-x64", "w_self_report.c", "format",
  "x86-64 console PE, the control case",
  pe=dict(PE64), expect={"ARGC": "1", "POINTER_BITS": "64", "DOUBLE_MATH": "1.000000",
                         "ARGV0_PRESENT": "yes"},
  notes="Every other format entry is compared against this one.")
S("pe-format-console-x64-O0", "w_self_report.c", "format",
  "the same source at -O0 with debug info", tc="mingw64-O0",
  pe={"pe_format": "PE32+", "subsystem_is_console": True, "has_symbol_table": True},
  expect={"ARGC": "1", "POINTER_BITS": "64", "DOUBLE_MATH": "1.000000"})
S("pe-format-console-x86", "w_self_report.c", "format",
  "32-bit PE32, running through WoW64", tc="mingw32-O2",
  pe={"pe_format": "PE32", "machine_is_x86_64": False, "subsystem_is_console": True},
  expect={"ARGC": "1", "POINTER_BITS": "32"},
  caps=["32-bit Windows support in the layer"],
  notes="i686-w64-mingw32 is genuinely installed here, so this is real coverage "
        "and not a claim.")
S("pe-format-console-clang", "w_self_report.c", "format",
  "built by clang targeting mingw, not by gcc", tc="clang-mingw64-O2",
  pe=dict(PE64), expect={"ARGC": "1", "POINTER_BITS": "64", "DOUBLE_MATH": "1.000000"})
S("pe-format-stripped", "w_self_report.c", "format", "stripped of its symbol table",
  cflags=["-s"], pe={"stripped": True, "has_symbol_table": False},
  expect={"ARGC": "1"})
S("pe-format-large-binary", "w_bigdata.c", "format", "a deliberately large PE",
  pe=dict(PE64), timeout=300.0,
  expect={"BIG_BYTES": "50331648", "BIG_FIRST": "yes", "BIG_LAST": "yes"},
  notes="48 MiB of initialised data, checksummed at runtime.")
S("pe-gui-window", "w_gui_window.c", "gui",
  "a real Win32 window with a message loop",
  cflags=["-mwindows", "-lgdi32"], gui=True, warmup=True, timeout=300.0,
  layers=["wine", "proton-wine"],
  pe={"subsystem_is_gui": True, "subsystem_is_console": False},
  expect={"REGISTER_CLASS": "yes", "CREATE_WINDOW": "yes", "WINDOW_VISIBLE": "yes",
          "WM_PAINT_SEEN": "yes", "WM_CLOSE_SEEN": "yes",
          "MESSAGES_DISPATCHED_NONZERO": "yes", "WINDOW_REACHED_SCREEN": "yes",
          "MESSAGE_LOOP_COMPLETED": "yes"},
  caps=["a display (runs ONLY on a private X server, never the real desktop)"],
  notes="Runs inside scripts/lib/private-display.sh. A GUI-subsystem PE has no "
        "console, so the oracle file is the only channel it has.")
S("pe-gui-window-no-display", "w_gui_window.c", "gui",
  "the same window program with no display at all",
  cflags=["-mwindows", "-lgdi32"], gui=False, layers=["wine", "proton-wine"],
  exit=1, result=False,
  pe={"subsystem_is_gui": True},
  expect={"REGISTER_CLASS": "yes", "CREATE_WINDOW": "no",
          "CREATE_WINDOW_ERROR": "ERROR_INVALID_WINDOW_HANDLE",
          "WINDOW_REACHED_SCREEN": "no"},
  notes="Declared failure mode, and a clean one: it reports why it could not "
        "create a window and exits 1 rather than hanging or crashing.")
S("pe-gui-headless-worker", "w_gui_headless.c", "gui",
  "a GUI-subsystem PE that never creates a window",
  cflags=["-mwindows"], gui=False, layers=["wine", "proton-wine"],
  pe={"subsystem_is_gui": True, "subsystem_is_console": False},
  effects=["creates headless.out"],
  expect={"SUBSYSTEM_DECLARED": "windows", "CREATES_WINDOW": "no",
          "NEEDS_DISPLAY": "no", "WROTE_OUTPUT_FILE": "yes",
          "COMPLETED_WITHOUT_DISPLAY": "yes"},
  post={"headless.out": ["HEADLESS_RAN=yes"]},
  notes="Real Windows software does this. A runtime that equates the GUI "
        "subsystem with needing a display is wrong about this specimen.")
S("pe-cxx-static-runtime", "x_cxx.cpp", "format",
  "C++ with the C++ runtime linked in",
  cflags=["-static-libstdc++", "-static-libgcc"],
  pe={"imports_excludes": ["libstdc++-6.dll"]},
  expect={"STATIC_INIT_ORDER": "12", "EXCEPTION_CAUGHT": "by-base-ref",
          "EXCEPTION_WHAT": "deliberate", "SORTED": "alpha,beta,gamma",
          "STATIC_INIT_BEFORE_MAIN": "yes", "EXCEPTION_UNWOUND": "yes"},
  notes="Static constructors, an unwound exception and iostreams with no runtime "
        "DLLs to ship.")
S("pe-cxx-bundled-runtime-dlls", "x_cxx.cpp", "format",
  "C++ against the shared C++ runtime, with those DLLs bundled beside it",
  stage="bundle_cxx_dlls",
  pe={"imports_contains": ["libstdc++-6.dll"]},
  expect={"STATIC_INIT_ORDER": "12", "EXCEPTION_CAUGHT": "by-base-ref",
          "SORTED": "alpha,beta,gamma", "EXCEPTION_UNWOUND": "yes"},
  caps=["libstdc++-6.dll, libgcc_s_seh-1.dll and libwinpthread-1.dll beside the exe"],
  notes="The bundled-runtime-DLL case done for real: the DLLs are copied next to "
        "the executable and nothing else is on the search path.")

# ---- streams, arguments, environment ------------------------------------
NATIVE = ["native", "wine", "proton-run", "proton-wine"]
STDIN_4K = bytes(((i * 37 + 11) & 0xFF) for i in range(4096))

S("pe-io-stdout-only", "p_streams.c", "io", "writes stdout and nothing else",
  argv=["out"], layers=NATIVE,
  expect={"STREAM_MODE": "out", "OUT_TOTAL": "8", "ERR_TOTAL": "0"},
  notes="Portable source, so the native cell is the same program.")
S("pe-io-stderr-only", "p_streams.c", "io", "writes stderr and nothing else",
  argv=["err"], layers=NATIVE,
  expect={"STREAM_MODE": "err", "OUT_TOTAL": "0", "ERR_TOTAL": "8"})
S("pe-io-both-streams", "p_streams.c", "io", "writes both streams",
  argv=["both"], layers=NATIVE,
  expect={"STREAM_MODE": "both", "OUT_TOTAL": "8", "ERR_TOTAL": "8"})
S("pe-io-stdin-consumed", "p_stdin.c", "io",
  "consumes 4096 binary bytes from stdin to EOF",
  argv=["binary"], stdin=STDIN_4K, layers=["native", "wine", "proton-wine"],
  expect={"STDIN_MODE_REQUESTED": "binary", "STDIN_BYTES": "4096",
          "STDIN_NOT_EMPTY": "yes", "AT_EOF": "yes"},
  expect_by_layer={"native": {"SETMODE_BINARY": "not-applicable"},
                   "wine": {"SETMODE_BINARY": "ok"},
                   "proton-wine": {"SETMODE_BINARY": "ok"}},
  caps=["stdin connected and closable"],
  notes="Declared for the three layers where stdin is a channel that exists. "
        "proton-run is deliberately excluded and covered by the probe below, "
        "because a specimen that quietly fails on one layer teaches nobody "
        "anything.")
S("pe-io-stdin-text-mode-ctrl-z", "p_stdin.c", "io",
  "the DOS end-of-file byte truncating stdin in text mode",
  argv=["text"], stdin=STDIN_4K, layers=["native", "wine", "proton-wine"],
  expect={"STDIN_MODE_REQUESTED": "text", "STDIN_NOT_EMPTY": "yes", "AT_EOF": "yes"},
  expect_by_layer={
      "native": {"STDIN_BYTES": "4096", "PLATFORM_HAS_TEXT_MODE": "no"},
      "wine": {"STDIN_BYTES": "35", "PLATFORM_HAS_TEXT_MODE": "yes"},
      "proton-wine": {"STDIN_BYTES": "35", "PLATFORM_HAS_TEXT_MODE": "yes"},
  },
  notes="A DELIBERATE per-layer difference, and the reason this specimen exists: "
        "the runner's 4096-byte input has its first 0x1A at offset 35, so a "
        "Windows program in the C runtime default text mode reads 35 bytes and "
        "reports a clean EOF, while the same source built for Linux reads all "
        "4096. This corpus first declared 4096 everywhere and its own baseline "
        "corrected it.")
S("pe-io-stdin-under-proton-run", "p_stdin.c", "io",
  "what Proton's launcher does with stdin",
  argv=["binary"], stdin=STDIN_4K, layers=["proton-run"], timeout=25.0,
  timeout_allowed=True, result=False, exit=None,
  expect_one_of={"STDIN_BYTES": ["4096", "<absent>"],
                 "RESULT": ["PASS", "<absent>"]},
  notes="MEASURED: under `proton run` the guest program starts -- it creates its "
        "oracle file and writes the first line -- and then blocks forever on its "
        "first read of stdin, even when stdin is /dev/null and should give an "
        "immediate EOF. The timeout IS the recorded outcome here, and the oracle "
        "file containing only its opening line is the evidence for how far it "
        "got. This is Proton's launcher, not the program and not .LEXE.")
S("pe-arg-narrow-basic", "p_args.c", "interface", "ordinary flags through argv",
  argv=["--flag", "-x", "value", "7"], layers=NATIVE,
  expect={"ARGC": "5", "ARG_1_LEN": "6", "ARG_1_HEX": "2d2d666c6167",
          "ARG_4_LEN": "1", "ARG_4_HEX": "37", "ARGV_NULL_TERMINATED": "yes"})
S("pe-arg-narrow-empty-and-spaces", "p_args.c", "interface",
  "empty, space-bearing and tab-bearing arguments",
  argv=["", "two words", " leading", "trailing ", "a\tb"], layers=NATIVE,
  expect={"ARGC": "6", "ARG_1_LEN": "0", "ARG_1_HEX": "",
          "ARG_2_LEN": "9", "ARG_2_HEX": "74776f20776f726473",
          "ARG_3_LEN": "8", "ARG_4_LEN": "9", "ARG_5_LEN": "3", "ARG_5_HEX": "610962"},
  notes="Windows rebuilds argv from a single command-line STRING, so an empty "
        "argument and a trailing space are the two things most likely to be lost.")
S("pe-arg-wide-unicode", "w_argsw.c", "interface",
  "UTF-8 arguments through GetCommandLineW and CommandLineToArgvW",
  cflags=["-lshell32"],
  argv=["café", "日本語", "Ωmega"],
  expect={"WARGC": "4", "COMMANDLINETOARGVW": "yes",
          "WARG_1_LEN": "5", "WARG_1_HEX": "636166c3a9",
          "WARG_2_LEN": "9", "WARG_2_HEX": "e697a5e69cace8aa9e",
          "WARG_3_LEN": "6", "WARG_3_HEX": "cea96d656761",
          "WIDE_ARGS_READ": "yes"},
  notes="The declared expectation is that a UTF-8 argument survives the trip "
        "through UTF-16 and back unchanged. Whether the layer manages that is "
        "exactly the question.")
S("pe-arg-wide-spaces-quotes", "w_argsw.c", "interface",
  "spaces and embedded quotes through the wide command line",
  cflags=["-lshell32"], argv=["two words", "trailing ", "has\"quote"],
  expect={"WARGC": "4", "COMMANDLINETOARGVW": "yes",
          "WARG_1_LEN": "9", "WARG_1_HEX": "74776f20776f726473",
          "WARG_2_LEN": "9", "WIDE_ARGS_READ": "yes"})
S("pe-env-narrow", "p_env.c", "interface", "environment variables through getenv",
  argv=["LEXE_WORKLOAD_TOKEN", "LEXE_WORKLOAD_EMPTY", "LEXE_WORKLOAD_NOT_SET"],
  env={"LEXE_WORKLOAD_TOKEN": "token-value-1", "LEXE_WORKLOAD_EMPTY": ""},
  layers=NATIVE,
  expect={"ENV_LEXE_WORKLOAD_TOKEN_PRESENT": "yes",
          "ENV_LEXE_WORKLOAD_TOKEN_LEN": "13",
          "ENV_LEXE_WORKLOAD_TOKEN_HEX": "746f6b656e2d76616c75652d31",
          "ENV_LEXE_WORKLOAD_NOT_SET_PRESENT": "no",
          "READ_ENVIRONMENT": "yes"},
  notes="An empty-but-present variable is not the same as an absent one, and "
        "Windows and POSIX do not agree about it by default.")
S("pe-env-wide-unicode", "w_envw.c", "interface",
  "a UTF-8 environment value through GetEnvironmentVariableW",
  argv=["LEXE_WORKLOAD_UNICODE"],
  env={"LEXE_WORKLOAD_UNICODE": "naïve-日本"},
  expect={"WENV_LEXE_WORKLOAD_UNICODE_PRESENT": "yes",
          "WENV_LEXE_WORKLOAD_UNICODE_LEN": "13",
          "WENV_LEXE_WORKLOAD_UNICODE_HEX": "6e61c3af76652de697a5e69cac",
          "WIDE_ENV_READ": "yes"})
S("pe-interface-module-path", "w_module_path.c", "interface",
  "GetModuleFileNameW against argv[0]",
  expect={"GET_MODULE_FILE_NAME": "yes", "MODULE_PATH_IS_ABSOLUTE": "yes",
          "MODULE_PATH_ENDS_IN_EXE": "yes", "HAVE_BOTH_VIEWS": "yes"},
  notes="A Windows module path is absolute with a drive letter, which is where "
        "the mapping a layer invents becomes visible.")
S("pe-layer-identity", "w_sysinfo.c", "layer",
  "what the layer says it is",
  expect={"IDENTITY_REPORTED": "yes"},
  notes="Every value here is an OBSERVATION on purpose. Wine and Proton "
        "legitimately differ, and this record says which two Windows they each "
        "claimed to be when something else disagreed.")

# ---- outcomes ------------------------------------------------------------
for _code in (0, 1, 42, 255):
    S("pe-outcome-exit-%d" % _code, "p_exit.c", "outcome",
      "exits with status %d after a complete run" % _code,
      argv=[str(_code)], exit=_code, layers=NATIVE,
      expect={"EXIT_CODE_INTENDED": str(_code), "WORK_DONE": "yes"},
      notes="RESULT=PASS with exit %d: the status is the declared outcome." % _code)
S("pe-outcome-abnormal-av", "w_abnormal.c", "outcome",
  "terminates on an access violation", argv=["av"],
  nonzero_exit=True, result=False, exit=None,
  expect={"ABNORMAL_MODE": "av", "WORK_BEFORE_FAULT": "done",
          "EXPECT_DEATH": "access-violation"},
  expect_absent=["RESULT", "UNREACHABLE"],
  notes="The oracle file is flushed per line, so it ends exactly at the fault. "
        "What STATUS each layer reports for an access violation is recorded per "
        "layer, not declared: the Win32 status (0xC0000005) and the status the "
        "Unix caller sees are not the same number.")
S("pe-outcome-abnormal-abort", "w_abnormal.c", "outcome",
  "terminates through the C runtime abort()", argv=["abort"],
  nonzero_exit=True, result=False, exit=None,
  expect={"ABNORMAL_MODE": "abort", "EXPECT_DEATH": "abort"},
  expect_absent=["RESULT"])
S("pe-outcome-abnormal-terminate", "w_abnormal.c", "outcome",
  "terminates itself with TerminateProcess and a chosen status",
  argv=["terminate"], exit=137, result=False,
  expect={"ABNORMAL_MODE": "terminate", "EXPECT_DEATH": "terminate-process-137"},
  expect_absent=["RESULT"],
  notes="TerminateProcess is the one abnormal exit whose status is chosen by the "
        "program, so it IS declared: 137.")
S("pe-outcome-abnormal-raise", "w_abnormal.c", "outcome",
  "raises an unhandled noncontinuable exception", argv=["raise"],
  result=False,
  exit_one_of_by_layer={"wine": [0, 66], "proton-wine": [66]},
  instability_expected="MEASURED over five repeats: the SYSTEM Wine is itself "
                       "nondeterministic here. Four repeats out of five resumed "
                       "execution and exited 0; the fifth killed the process with "
                       "exit 66. Proton's Wine gave 66 in all five. The specimen is "
                       "unchanged between repeats, so the nondeterminism belongs to "
                       "the layer, and it is DECLARED here rather than discovered "
                       "later as a mystery failure. Four repeats would have called "
                       "this stable.",
  expect={"ABNORMAL_MODE": "raise", "EXPECT_DEATH": "raise-exception-0xE0000042"},
  expect_one_of={"PROCESS_SURVIVED_UNHANDLED_EXCEPTION": ["yes", "<absent>"],
                 "RESULT": ["PASS", "<absent>"]},
  notes="A DELIBERATE per-layer difference, and the sharpest Wine-versus-Proton "
        "finding in this corpus. On Windows an unhandled NONCONTINUABLE exception "
        "ends the process. The SYSTEM Wine, with no debugger attached, RETURNS from "
        "the unhandled-exception path and execution resumes: the specimen records "
        "PROCESS_SURVIVED_UNHANDLED_EXCEPTION=yes and exits 0. PROTON's Wine kills "
        "the process, and its exit status is 66 -- which is 0x42, the low byte of "
        "the 0xE0000042 exception code this specimen chose. Same program, same "
        "prefix layout, two different outcomes from two Wines -- and the system "
        "Wine does not even give the same answer twice: see instability_expected. "
        "The first version of this entry declared one outcome for every layer, and "
        "its own baseline corrected it twice: first on the layer difference, then "
        "on the nondeterminism.")
S("pe-run-bounded-500ms", "w_longrun.c", "outcome", "a bounded sub-second run",
  argv=["500"],
  expect={"SLEEP_REQUESTED_MS": "500", "SLEEP_FLOOR_MS": "450",
          "SLEPT_AT_LEAST_REQUESTED": "yes", "SLEEP_WAS_NOT_SKIPPED": "yes",
          "DURATION_CLASS": "sub-second"})
S("pe-run-bounded-3s", "w_longrun.c", "outcome", "a long-running process",
  argv=["3000"], duration="seconds", timeout=180.0,
  expect={"SLEEP_REQUESTED_MS": "3000", "SLEEP_FLOOR_MS": "2700",
          "SLEPT_AT_LEAST_REQUESTED": "yes", "SLEEP_WAS_NOT_SKIPPED": "yes",
          "DURATION_CLASS": "seconds"},
  notes="DECLARATION REVISED, and the revision is a finding about the layer rather "
        "than about the program. The original check required the elapsed "
        "QueryPerformanceCounter time to be within 20 ms of the requested 3000, and "
        "on a busy host it failed at 2962 ms -- under BOTH Wines, across repeats. "
        "Sleep did not return early in any useful sense: Sleep and "
        "QueryPerformanceCounter are different clocks in this layer and they do not "
        "agree to better than a few tens of milliseconds under load. A 20 ms window "
        "on 3000 ms is 0.67%, which made this a PERFORMANCE assertion disguised as a "
        "correctness one -- the exact thing this corpus forbids everywhere else, and "
        "it had been sitting here passing quietly on an idle machine. The "
        "deterministic check is now the one that really separates a working Sleep "
        "from a broken one, and the clock disagreement is reported as "
        "OBS_SLEEP_VERSUS_QPC_MS and OBS_QPC_AGREED_WITHIN_20MS, where it is "
        "visible instead of fatal.")
S("pe-run-cpu-bound", "p_cpu.c", "outcome", "a deterministic CPU-bound run",
  argv=["20000000"], layers=NATIVE, duration="seconds", timeout=180.0,
  expect={"ROUNDS": "20000000", "WORK_COMPLETED": "yes"},
  notes="CHECKSUM is not declared here because it is not a property of Windows: "
        "it is compared across every layer AND every toolchain, and it must be "
        "bit-identical everywhere including natively.")

# ---- filesystem ----------------------------------------------------------
S("pe-fs-portable-file", "p_files.c", "filesystem",
  "create, write, read back, rename, delete", layers=NATIVE,
  effects=["creates and removes work.tmp and work.final"],
  expect={"CREATE": "yes", "WRITE": "yes", "REOPEN": "yes", "READ_BYTES": "25",
          "CONTENT_MATCHES": "yes", "RENAME": "yes", "OLD_NAME_GONE": "yes",
          "NEW_NAME_PRESENT": "yes", "DELETE": "yes", "DELETED": "yes"})
S("pe-fs-tempfile", "w_tempfile.c", "filesystem",
  "GetTempPathW and GetTempFileNameW",
  expect={"GET_TEMP_PATH": "yes", "GET_TEMP_FILE_NAME": "yes", "OPEN_TEMP": "yes",
          "WRITE_TEMP": "yes", "DELETE_TEMP": "yes", "TEMP_GONE": "yes",
          "LEAVES_NO_TRACE": "yes"},
  caps=["a usable Windows temp path"])
S("pe-fs-persistent-state", "w_persist.c", "filesystem",
  "state that survives between two launches", runs=2,
  effects=["appends one line to state.dat per launch"],
  expect={"OPEN_APPEND": "yes", "FLUSH": "yes", "AT_LEAST_ONE_RUN": "yes"},
  caps=["a writable directory that persists between launches"],
  notes="Launched twice per repeat: RUN_COUNT must read 1 then 2.")
S("pe-fs-cwd-relative-asset", "w_cwd_asset.c", "filesystem",
  "a working-directory assumption with a backslash path",
  files={"assets/data.txt": "relative-asset-v1\n"},
  expect={"ASSET_OPENED_BACKSLASH": "yes", "ASSET_CONTENT": "relative-asset-v1",
          "ASSET_CONTENT_OK": "yes"},
  caps=["the working directory is where the asset is"])
S("pe-fs-unicode-path", "w_unicode_path.c", "filesystem",
  "a file whose name is not ASCII",
  effects=["creates and deletes a file with a Japanese and accented name"],
  expect={"TARGET_NAME_LEN": "19",
          "TARGET_NAME_HEX": "e697a5e69cace8aa9e2d636166c3a92e747874",
          "CREATE_FILE_W": "yes", "WRITE_FILE": "yes", "BYTES_WRITTEN": "20",
          "FIND_FIRST_FILE_W": "yes",
          "FOUND_NAME_HEX": "e697a5e69cace8aa9e2d636166c3a92e747874",
          "REOPEN_BY_UNICODE_NAME": "yes", "CONTENT_MATCHES": "yes",
          "DELETE_FILE_W": "yes", "GONE": "yes"},
  notes="The name is built from code points in the source, so the encoding of the "
        "source file cannot change what is being tested.")
S("pe-fs-directory-tree", "w_dirtree.c", "filesystem",
  "CreateDirectoryW and a FindFirstFileW walk",
  effects=["creates tree/ with 6 directories and 20 files"],
  expect={"DIRS_FOUND": "6", "FILES_FOUND": "20", "TREE_SHAPE": "yes"})
S("pe-registry-roundtrip", "w_registry.c", "registry",
  "a registry key written, read back and deleted",
  effects=["creates and removes HKCU/Software/LexeWorkload/Probe"],
  expect={"REG_CREATE": "yes", "KEY_WAS_CREATED_NOT_OPENED": "yes", "SET_SZ": "yes",
          "SET_DWORD": "yes", "QUERY_SZ": "yes", "SZ_TYPE_IS_REG_SZ": "yes",
          "SZ_VALUE_LEN": "16",
          "SZ_VALUE_HEX": "72656769737472792d746f6b656e2d31",
          "QUERY_DWORD": "yes", "DWORD_TYPE_IS_REG_DWORD": "yes",
          "DWORD_VALUE": "48879", "DWORD_ROUNDTRIPPED": "yes", "REG_DELETE": "yes"},
  caps=["a writable registry"],
  notes="There is no POSIX equivalent to pretend about: either the layer has a "
        "registry or it does not.")

# ---- DLL loading ---------------------------------------------------------
S("pe-dll-implicit-bundled", "w_dll_implicit.c", "dll",
  "an implicit import from a DLL bundled beside the exe",
  stage="bundle_wlib", pe={"imports_contains": ["wlib.dll"]},
  effects=["the DLL writes dllmain.log on process attach"],
  expect={"LIB_VALUE": "1234", "LIB_NAME": "lexe-workload-dll",
          "LIB_POINTER_BITS": "64", "IMPORT_RESOLVED": "yes", "DLLMAIN_RAN": "yes"},
  caps=["wlib.dll beside the executable"],
  notes="DllMain writing a file is the evidence that the DLL was really loaded "
        "and initialised, not merely resolved.")
S("pe-dll-implicit-missing", "w_dll_implicit.c", "dll",
  "the same exe with its DLL absent: the process cannot start at all",
  stage="isolate_exe", pe={"imports_contains": ["wlib.dll"]},
  nonzero_exit=True, result=False, exit=None,
  expect={}, expect_absent=["RESULT", "LIB_VALUE"],
  notes="There is no code in the program that can run to report this, so the "
        "evidence IS the absence of an oracle file plus the loader's status. The "
        "status each layer reports for a missing import is recorded per layer.")
S("pe-dll-explicit-present", "w_dll_explicit.c", "dll",
  "LoadLibraryW and GetProcAddress on a DLL that is there",
  stage="bundle_wlib", argv=["wlib.dll", "ok"],
  expect={"EXPECTATION": "ok", "LOADLIBRARY": "ok", "OUTCOME_AS_DECLARED": "yes",
          "GETPROCADDRESS_VALUE": "yes", "LIB_VALUE": "1234",
          "LIB_POINTER_BITS": "64", "MISSING_SYMBOL_REPORTS_NULL": "yes",
          "FREE_LIBRARY": "yes"},
  caps=["dynamic loading at runtime"])
S("pe-dll-explicit-missing", "w_dll_explicit.c", "dll",
  "LoadLibraryW on a DLL that does not exist, handled rather than fatal",
  stage="bundle_wlib", argv=["no-such-library.dll", "fail"],
  expect={"EXPECTATION": "fail", "LOADLIBRARY": "fail",
          "LOAD_ERROR": "ERROR_MOD_NOT_FOUND", "OUTCOME_AS_DECLARED": "yes"},
  notes="Refusing to load a DLL that is not there is correct behaviour, so this "
        "specimen exits 0 with RESULT=PASS.")
S("pe-dll-explicit-wrong-arch", "w_dll_explicit.c", "dll",
  "LoadLibraryW on a 32-bit DLL from a 64-bit process",
  stage="bundle_wlib", argv=["wlib32.dll", "fail"],
  expect={"EXPECTATION": "fail", "LOADLIBRARY": "fail",
          "LOAD_ERROR": "ERROR_BAD_EXE_FORMAT", "OUTCOME_AS_DECLARED": "yes"},
  caps=["a 32-bit DLL built by i686-w64-mingw32, beside a 64-bit exe"],
  notes="The wrong-architecture case has its own distinct error, and a layer that "
        "collapsed it into ERROR_MOD_NOT_FOUND would be losing information a real "
        "installer depends on.")

# ---- threads, synchronisation, IPC --------------------------------------
S("pe-proc-threads-4", "w_threads.c", "process", "four Win32 threads, joined",
  argv=["4"], procbeh="multi-threaded",
  expect={"THREADS_REQUESTED": "4", "THREADS_STARTED": "4", "TOTAL": "3839146",
          "ALL_THREADS_STARTED": "yes"},
  notes="CreateThread and a CRITICAL_SECTION, not pthreads. TOTAL is the same "
        "number the Linux corpus computes for four threads, independently.")
S("pe-proc-threads-64", "w_threads.c", "process", "sixty-four Win32 threads",
  argv=["64"], procbeh="multi-threaded", timeout=180.0,
  expect={"THREADS_REQUESTED": "64", "THREADS_STARTED": "64",
          "ALL_THREADS_STARTED": "yes"},
  caps=["64 concurrent threads"],
  notes="Also crosses the WaitForMultipleObjects limit of 64 handles, which is "
        "why the specimen waits in batches.")
S("pe-sync-named-mutex", "w_named_mutex.c", "process",
  "a named mutex, opened twice, that really serialises",
  procbeh="multi-threaded",
  expect={"CREATE_FIRST": "yes", "FIRST_WAS_NEW": "yes",
          "CREATE_SECOND_HANDLE": "yes", "SECOND_REPORTS_ALREADY_EXISTS": "yes",
          "PROBE_THREAD": "yes", "PROBE_RESULT": "0", "MUTEX_SERIALISED": "yes"},
  caps=["named kernel objects"])
S("pe-sync-event-handoff", "w_event.c", "process",
  "an event object ordering two threads deterministically",
  procbeh="multi-threaded",
  expect={"EVENTS_CREATED": "yes", "THREAD_CREATED": "yes",
          "WORKER_RAN_BEFORE_SIGNAL": "no", "HANDOFF_COMPLETED": "yes",
          "WORKER_RAN_AFTER_SIGNAL": "yes"})
S("pe-ipc-named-pipe", "w_namedpipe.c", "process",
  "a Windows named pipe, served and consumed in one process",
  procbeh="multi-threaded",
  expect={"CREATE_NAMED_PIPE": "yes", "CLIENT_THREAD": "yes",
          "CONNECT_NAMED_PIPE": "yes", "SERVER_READ": "yes",
          "SERVER_RECEIVED": "PIPE-PING", "PING_CORRECT": "yes",
          "SERVER_WRITE": "yes", "CLIENT_RESULT": "0",
          "CLIENT_ROUNDTRIP_OK": "yes"},
  caps=["named pipes"])

# ---- sockets -------------------------------------------------------------
S("pe-socket-tcp-loopback", "w_tcp.c", "sockets",
  "Winsock TCP over loopback", cflags=["-lws2_32"],
  expect={"WSASTARTUP": "ok", "ACCEPT": "ok", "RECEIVED": "HELLO-TCP",
          "TCP_LOOPBACK": "ok", "SURVIVED_NETWORK_ATTEMPT": "yes"},
  caps=["loopback networking"],
  notes="Declared for an unconfined host. A runtime that denies networking gets "
        "TCP_LOOPBACK=unavailable with the failing stage and the Winsock error "
        "named, which is a legitimate observation and not a specimen failure.")
S("pe-socket-udp-loopback", "w_udp.c", "sockets",
  "one Winsock UDP datagram over loopback", cflags=["-lws2_32"],
  expect={"RECEIVED": "DGRAM-1", "UDP_LOOPBACK": "ok",
          "SURVIVED_NETWORK_ATTEMPT": "yes"},
  caps=["loopback networking"])
S("pe-socket-name-resolution", "w_resolve.c", "sockets",
  "Winsock resolver behaviour for a local and a bogus name", cflags=["-lws2_32"],
  expect={"LOCALHOST_RC_IS_ZERO": "yes", "LOCALHOST_ADDRS_NONZERO": "yes",
          "BOGUS_RC_IS_ZERO": "no", "SURVIVED_RESOLUTION": "yes"},
  caps=["name resolution for localhost"])
S("pe-socket-tcp6-loopback", "w_tcp6.c", "sockets",
  "Winsock TCP over IPv6 loopback", cflags=["-lws2_32"],
  expect={"WSASTARTUP": "ok", "AF_INET6_SOCKET": "ok", "BOUND_LOOPBACK_V6": "ok",
          "ACCEPT": "ok", "RECEIVED": "HELLO-TCP6", "TCP6_LOOPBACK": "ok",
          "PEER_FAMILY_IS_INET6": "yes", "PEER_IS_V6_LOOPBACK": "yes",
          "SURVIVED_NETWORK_ATTEMPT": "yes"},
  caps=["IPv6 loopback"],
  notes="A different address family, a different sockaddr and, inside a "
        "translation layer, often a different amount of implementation. Working on "
        "IPv4 loopback and not on IPv6 loopback is a real and common failure, so "
        "the two are separate cells and never one 'networking' cell.")
S("pe-socket-select-nonblocking", "w_select.c", "sockets",
  "non-blocking sockets and the three answers select can give",
  cflags=["-lws2_32"],
  expect={"CLIENT_SOCKET": "yes", "SET_NON_BLOCKING": "yes",
          "SELECT_WRITABLE_AFTER_CONNECT": "1",
          "CONNECT_COMPLETED_VIA_SELECT": "yes", "ACCEPTED": "yes",
          "SET_ACCEPTED_NON_BLOCKING": "yes", "SELECT_READ_WHEN_IDLE": "0",
          "IDLE_SOCKET_NOT_READABLE": "yes", "NONBLOCKING_RECV_WHEN_IDLE": "-1",
          "NONBLOCKING_RECV_ERROR": "WSAEWOULDBLOCK",
          "SELECT_READ_WITH_DATA": "1", "RECEIVED": "SELECT-PING",
          "READY_SOCKET_DELIVERED_THE_DATA": "yes", "SELECT_MODEL": "ok",
          "SURVIVED_NETWORK_ATTEMPT": "yes"},
  expect_one_of={"NONBLOCKING_CONNECT": ["would-block", "completed-immediately"]},
  caps=["loopback networking"],
  notes="The READINESS model rather than the blocking one. Whether a non-blocking "
        "connect over loopback reports WSAEWOULDBLOCK or completes synchronously is "
        "a PLATFORM choice -- Windows always defers it, a Unix kernel behind a "
        "layer need not -- so that one key is expect_one_of and everything else, "
        "including a select that must return 0 on an idle socket, stays exact.")
S("pe-socket-error-paths", "w_connrefused.c", "sockets",
  "four socket failures, each with its own distinct Winsock error",
  cflags=["-lws2_32"],
  expect={"SOCKET": "yes", "CONNECT_TO_DEAD_PORT": "refused",
          "CONNECT_TO_DEAD_PORT_ERROR": "WSAECONNREFUSED",
          "SEND_UNCONNECTED": "-1", "SEND_UNCONNECTED_ERROR": "WSAECONNRESET",
          "FIRST_BIND": "yes", "SECOND_BIND_SAME_ADDRESS": "refused",
          "SECOND_BIND_ERROR": "WSAEADDRINUSE",
          "SEND_ON_CLOSED_SOCKET": "-1",
          "SEND_ON_CLOSED_SOCKET_ERROR": "WSAENOTSOCK",
          "SOCKET_AFTER_WSACLEANUP": "refused",
          "SOCKET_AFTER_WSACLEANUP_ERROR": "WSANOTINITIALISED",
          "SURVIVED_EVERY_ERROR_PATH": "yes"},
  caps=["loopback networking"],
  notes="The happy-path socket specimens cannot see any of this. Four DISTINCT "
        "errors, because a networked application branches on which one it got, and "
        "a layer that collapsed them into one would make 'nobody is listening' and "
        "'my socket is closed' indistinguishable. The dead port is obtained "
        "honestly: bound, read back, then closed. DECLARATION REVISED BY ITS OWN "
        "BASELINE, and worth writing down: I declared WSAENOTCONN for a send on a "
        "socket that was never connected, which is what Windows documents. The "
        "measured answer here is WSAECONNRESET -- Wine is relaying the Unix EPIPE "
        "from a send() on an unconnected TCP socket rather than synthesising the "
        "Win32 error. The declaration now records what this platform actually does, "
        "and the difference from documented Windows is stated rather than smoothed "
        "over: it is the kind of thing that makes a reconnect loop behave "
        "differently under a translation layer than on Windows, because "
        "WSAECONNRESET reads as 'the peer went away, retry' and WSAENOTCONN reads "
        "as 'you have a bug'. The other three errors in this specimen came back "
        "exactly as declared.")

# ---- large, binary and paced output --------------------------------------
#
# The deterministic claims in this family are about a FILE the specimen writes that
# carries nothing but the payload -- never an offset, length or count over a stream
# that also carries FIXTURE_ID. FIXTURE_ID is environment-derived, and an offset
# measured past it moves when the environment does. In the STREAM the payload is
# located by its delimiter LINES, by content; any absolute offset is an OBS_.

_BULK_COMMON = {"BULK_LINE_BYTES": "64", "BULK_FILE_OPEN": "yes",
                "BULK_FILE_REOPEN": "yes", "BULK_FILE_SIZE_AS_INTENDED": "yes",
                "BULK_EMITTED": "yes",
                "BULK_DELIMITERS": "BULK_PAYLOAD_BEGIN..BULK_PAYLOAD_END"}
_BULK_256 = dict(_BULK_COMMON, BULK_KIB="256", BULK_FILE_BYTES="262144",
                 BULK_ROLLING_HASH="0c59b1d115cf0325",
                 BULK_FILE_HASH="368ae29b2e800325")

S("pe-io-bulk-stdout-256k", "w_bulkout.c", "io",
  "256 KiB of payload on stdout between two delimiter lines",
  argv=["out", "256"], layers=NATIVE, timeout=180.0,
  expect=dict(_BULK_256, BULK_STREAM="out"),
  notes="Large output as a dimension in its own right: a consumer that reads a "
        "guest's stdout has to survive a quarter of a megabyte arriving in one "
        "burst. The payload is lowercase hex and newlines only, so it cannot "
        "contain either delimiter, and the hash is over bulk.bin -- a file that "
        "never carried FIXTURE_ID -- so it is a property of the program.")
S("pe-io-bulk-stderr-256k", "w_bulkout.c", "io",
  "256 KiB of payload on stderr instead",
  argv=["err", "256"], layers=NATIVE, timeout=180.0,
  expect=dict(_BULK_256, BULK_STREAM="err"),
  notes="Separate from the stdout case because the two streams are separately "
        "buffered and separately plumbed, and a consumer that drains one while the "
        "other fills its pipe deadlocks.")
S("pe-io-bulk-both-256k", "w_bulkout.c", "io",
  "256 KiB on BOTH streams at once, interleaved",
  argv=["both", "256"], layers=NATIVE, timeout=180.0,
  expect=dict(_BULK_256, BULK_STREAM="both"),
  notes="The deadlock case: half a megabyte in total, going out of two pipes at "
        "the same time. Anything reading one stream to EOF before starting on the "
        "other hangs here and nowhere else in the corpus.")
S("pe-io-bulk-stdout-4m", "w_bulkout.c", "io",
  "4 MiB on stdout: an order of magnitude past the pipe buffer",
  argv=["out", "4096"], layers=NATIVE, timeout=300.0, duration="seconds",
  expect=dict(_BULK_COMMON, BULK_STREAM="out", BULK_KIB="4096",
              BULK_FILE_BYTES="4194304",
              BULK_ROLLING_HASH="3c980e4214242325",
              BULK_FILE_HASH="068b7c5f2a002325"),
  notes="The 256 KiB cases fit in a few pipe buffers; this one does not, by a long "
        "way, so the writer really does block on the reader repeatedly.")
S("pe-io-binary-nul", "w_binout.c", "io",
  "binary output including NUL bytes, newlines and DOS EOFs",
  layers=NATIVE, timeout=120.0,
  expect={"BIN_FILE_OPEN": "yes", "BIN_FILE_REOPEN": "yes",
          "BIN_FILE_BYTES": "1024", "BIN_FILE_HASH": "1e5698f9d66e6f25",
          "BIN_DISTINCT_BYTE_VALUES": "256", "BIN_NUL_COUNT": "4",
          "BIN_NEWLINE_COUNT": "4", "BIN_DOS_EOF_COUNT": "4",
          "BIN_ROUNDTRIP_IDENTICAL": "yes", "BIN_NO_NEWLINE_TRANSLATION": "yes",
          "BIN_EMITTED": "yes",
          "BIN_DELIMITERS": "BIN_PAYLOAD_BEGIN..BIN_PAYLOAD_END"},
  expect_by_layer={"native": {"STDOUT_BINARY_MODE": "not-applicable"},
                   "wine": {"STDOUT_BINARY_MODE": "ok"},
                   "proton-wine": {"STDOUT_BINARY_MODE": "ok"}},
  notes="All 256 byte values, four times over. The Windows-specific part is that "
        "stdout must be put into _O_BINARY first or the C runtime turns every 0x0A "
        "in the payload into 0x0D 0x0A -- the same text-mode machinery that "
        "truncates stdin at 0x1A in pe-io-stdin-text-mode-ctrl-z, seen from the "
        "other end. The declared per-layer difference is only that a Linux build "
        "has no such mode to ask for.")
S("pe-io-paced-output", "w_paced.c", "io",
  "twelve lines a quarter of a second apart, on both streams and to a file",
  argv=["12", "250"], duration="seconds", timeout=180.0,
  expect={"PACED_LINES_REQUESTED": "12", "PACE_INTERVAL_MS": "250",
          "PACED_LOG_OPEN": "yes", "PACED_LOG_REOPEN": "yes",
          "PACED_LOG_LINES": "12", "PACED_ALL_LINES_LANDED": "yes",
          "DURATION_CLASS": "seconds"},
  notes="A program that dribbles output over three seconds, which is where a "
        "consumer that buffers until EOF behaves differently from one that streams. "
        "paced.log carries nothing but the paced lines, so its line COUNT is a "
        "property of the program; the elapsed time is an observation, always. "
        "That last clause used to be false of this entry: it also declared "
        "PACED_TOOK_AT_LEAST_THE_GAPS=yes, a deterministic assertion about "
        "elapsed wall time, and it failed on two of five IDENTICAL repeats under "
        "both Wine layers -- 2560, 2766, 2729, 2664 and 2765 ms against an "
        "11 x 250 ms floor of 2690. Sleep(n) does not promise to take n ms and on "
        "a translation layer it often returns early, so the floor is a fact about "
        "the LAYER and the specimen was reporting the host's timer as a fixture "
        "failure. It is an observation now, with the number beside it.")
S("pe-io-standard-handles", "w_console.c", "io",
  "what the standard handles ARE, not what is written to them",
  expect={"STDIN_HANDLE_VALID": "yes",
          "STDOUT_HANDLE_VALID": "yes",
          "STDERR_HANDLE_VALID": "yes",
          "STDIN_GETCONSOLEMODE": "fail", "STDOUT_GETCONSOLEMODE": "fail",
          "STDERR_GETCONSOLEMODE": "fail",
          "STDIN_GETCONSOLEMODE_ERROR": "ERROR_INVALID_HANDLE",
          "STDOUT_GETCONSOLEMODE_ERROR": "ERROR_INVALID_HANDLE",
          "STDERR_GETCONSOLEMODE_ERROR": "ERROR_INVALID_HANDLE",
          "STD_HANDLES_ARE_DISTINCT": "yes",
          "WRITEFILE_TO_STD_HANDLE": "yes", "RAW_WRITEFILE_BYTES": "18",
          "RAW_WRITE_WROTE_EVERYTHING": "yes", "OPENED_REROUTE_TARGET": "yes",
          "SET_STD_HANDLE": "yes", "RESTORED_STD_HANDLE": "yes",
          "STD_HANDLE_IS_BACK": "yes", "REROUTED_FILE_BYTES": "13",
          "REROUTED_WRITE_LANDED_IN_THE_FILE": "yes"},
  expect_by_layer={
      "wine": {"STDIN_FILE_TYPE": "pipe", "STDOUT_FILE_TYPE": "pipe",
               "STDERR_FILE_TYPE": "pipe"},
      "proton-wine": {"STDIN_FILE_TYPE": "char", "STDOUT_FILE_TYPE": "char",
                      "STDERR_FILE_TYPE": "char"},
  },
  notes="A DELIBERATE per-layer difference, MEASURED, and one of the sharper "
        "Wine-versus-Proton findings in this corpus. The generator hands every "
        "specimen the SAME three pipes on every layer -- that is a property of the "
        "harness, not of the guest -- and yet the system Wine reports all three as "
        "FILE_TYPE_PIPE while PROTON's Wine reports all three as FILE_TYPE_CHAR, a "
        "character device. Both then fail GetConsoleMode with ERROR_INVALID_HANDLE, "
        "so under Proton's Wine the two questions a program asks to decide whether "
        "it is running interactively give CONTRADICTORY answers: GetFileType says "
        "'a console-like device', GetConsoleMode says 'not a console'. A great deal "
        "of real Windows software branches on exactly this -- coloured output, "
        "progress bars, prompting -- and it will branch differently under the two "
        "layers. I declared 'pipe' everywhere and the baseline corrected me. The "
        "last block redirects the process's OWN stdout handle at runtime and puts "
        "it back, which is how a program captures a library's output.")

# ---- unusual exit codes ---------------------------------------------------
#
# A Windows exit status is a full 32-bit DWORD and a Unix wait status carries eight
# bits, so a translation layer has to truncate -- and the specimen's own oracle FILE
# is what preserves the intent across that truncation.
S("pe-outcome-exit-256", "w_exitcode.c", "outcome",
  "exits 256: the one truncation that is NOT a plain & 0xFF",
  argv=["256"], exit=1,
  expect={"EXIT_CODE_INTENDED": "256", "EXIT_CODE_INTENDED_HEX": "0x00000100",
          "EXIT_CODE_LOW_BYTE": "0", "EXIT_CODE_EXCEEDS_8_BITS": "yes",
          "EXIT_CODE_LOOKS_LIKE_NT_STATUS": "no", "DIED_ABNORMALLY": "no",
          "WORK_DONE": "yes"},
  notes="DECLARATION REVISED BY ITS OWN BASELINE, and the revision is the finding. "
        "I declared exit 0, reasoning that a Unix wait status is eight bits and "
        "256 & 0xFF is 0. The other two specimens in this family confirm that "
        "reasoning exactly -- 1000 truncates to 232 and 0xC0000005 truncates to 5, "
        "both as declared -- but 256 came back as 1, not 0. So the mapping is NOT a "
        "plain & 0xFF: a non-zero Windows status whose low byte happens to be zero "
        "is reported as 1 rather than allowed to become a SUCCESS. That is sensible "
        "behaviour and I had not predicted it; it is also a fact a supervisor needs, "
        "because it means the exact status is lost while the failure is not. Which "
        "of the two is worse depends on the caller, and the oracle file is where the "
        "full 32-bit intent survives either way.")
S("pe-outcome-exit-1000", "w_exitcode.c", "outcome",
  "exits 1000, which truncates to 232",
  argv=["1000"], exit=232,
  expect={"EXIT_CODE_INTENDED": "1000", "EXIT_CODE_INTENDED_HEX": "0x000003e8",
          "EXIT_CODE_LOW_BYTE": "232", "EXIT_CODE_EXCEEDS_8_BITS": "yes",
          "EXIT_CODE_LOOKS_LIKE_NT_STATUS": "no", "WORK_DONE": "yes"},
  notes="1000 & 0xFF is 232. Declared before running from the same reasoning.")
S("pe-outcome-exit-looks-like-a-crash", "w_exitcode.c", "outcome",
  "exits 0xC0000005 ON PURPOSE, which looks exactly like an access violation",
  argv=["3221225477"], exit=5,
  expect={"EXIT_CODE_INTENDED": "3221225477",
          "EXIT_CODE_INTENDED_HEX": "0xc0000005", "EXIT_CODE_LOW_BYTE": "5",
          "EXIT_CODE_EXCEEDS_8_BITS": "yes",
          "EXIT_CODE_LOOKS_LIKE_NT_STATUS": "yes", "DIED_ABNORMALLY": "no",
          "WORK_DONE": "yes"},
  notes="The sharpest of the three. This program did not crash: it ran to "
        "completion, wrote a full oracle with RESULT=PASS, and then chose to exit "
        "with the same 32-bit value an access violation produces. A parent using "
        "GetExitCodeProcess sees 0xC0000005 and a Unix caller sees 5 -- both "
        "identical to pe-outcome-abnormal-av -- and the ONLY thing that "
        "distinguishes the two is the oracle file. Declared exit 5 from the "
        "definition of a Unix wait status, before running.")
for _code in (2, 127):
    S("pe-outcome-exit-%d" % _code, "p_exit.c", "outcome",
      "exits with status %d after a complete run" % _code,
      argv=[str(_code)], exit=_code, layers=NATIVE,
      expect={"EXIT_CODE_INTENDED": str(_code), "WORK_DONE": "yes"},
      notes="Two more conventional statuses with meanings of their own: 2 is the "
            "usage convention and 127 is 'command not found' in a shell, so both "
            "are statuses a supervisor is likely to interpret rather than pass on.")

# ---- DLL search order -----------------------------------------------------
#
# Two DLLs with the SAME FILE NAME and different exports, so the specimen can say
# WHICH one the loader found. A test that only checks "LoadLibrary succeeded"
# cannot tell the application directory from a directory added at runtime.
S("pe-dll-search-appdir-wins", "w_dll_search.c", "dll",
  "the application directory beats a directory added to the search path",
  stage="search_both", argv=["appdir"],
  expect={"SEARCH_MODE": "appdir", "MODULE_DIR_FOUND": "yes",
          "ALT_DLL_IS_STAGED": "yes", "LOAD": "ok", "LOADED": "yes",
          "LOADED_WHICH": "primary", "LOADED_VALUE": "1111",
          "APPLICATION_DIRECTORY_WON": "yes"},
  caps=["two same-named DLLs in two directories"],
  notes="Both DLLs are present and they are DIFFERENT: search_which() is what makes "
        "the answer observable at all.")
S("pe-dll-search-setdlldirectory", "w_dll_search.c", "dll",
  "SetDllDirectoryW turning a failed load into a successful one",
  stage="search_alt_only", argv=["needs-setdll"],
  expect={"SEARCH_MODE": "needs-setdll", "ALT_DLL_IS_STAGED": "yes",
          "FIRST_LOAD": "fail", "FIRST_LOAD_ERROR": "ERROR_MOD_NOT_FOUND",
          "FIRST_LOAD_FAILED_AS_DECLARED": "yes", "SETDLLDIRECTORY": "yes",
          "SECOND_LOAD": "ok", "SECOND_LOAD_SUCCEEDED": "yes",
          "LOADED_WHICH": "alt", "LOADED_VALUE": "2222",
          "SETDLLDIRECTORY_CHANGED_THE_OUTCOME": "yes"},
  caps=["SetDllDirectoryW"],
  notes="The DLL is staged ONLY in altdir, so the first load must fail. The "
        "evidence that SetDllDirectory did something is the CHANGE in outcome "
        "between two otherwise identical calls in one process -- not the second "
        "call succeeding, which could have happened for any number of reasons.")
S("pe-dll-search-absolute-path", "w_dll_search.c", "dll",
  "an absolute path, which performs no search at all",
  stage="search_alt_only", argv=["explicit-abs"],
  expect={"SEARCH_MODE": "explicit-abs", "LOAD": "ok", "LOADED": "yes",
          "LOADED_WHICH": "alt", "LOADED_VALUE": "2222",
          "NO_SEARCH_PERFORMED": "yes"},
  notes="The control for the other three: the same DLL in the same place, reached "
        "without the search path being involved.")
S("pe-dll-search-adddlldirectory", "w_dll_search.c", "dll",
  "the modern SetDefaultDllDirectories/AddDllDirectory pair, if it exists",
  stage="search_alt_only", argv=["adddlldirectory"],
  expect={"SEARCH_MODE": "adddlldirectory", "MODERN_SEARCH_API_PROBED": "yes",
          "ALT_DLL_IS_STAGED": "yes"},
  expect_one_of={"MODERN_SEARCH_API_PRESENT": ["yes", "no"],
                 "LOAD": ["ok", "not-attempted"],
                 "LOADED_WHICH": ["alt", "<absent>"]},
  notes="Whether these two entry points exist at all is a property of the Windows "
        "being emulated, not of the program, so their presence is an OBSERVATION "
        "and the outcome is declared as either legitimate possibility. What IS "
        "declared is that the program probes them and survives either answer -- a "
        "specimen that silently did nothing when they were missing would be a row "
        "pretending to be coverage.")

# ---- the registry, past a single round trip -------------------------------
S("pe-registry-enumerate", "w_registry2.c", "registry",
  "subkeys and values counted, then walked to ERROR_NO_MORE_ITEMS",
  argv=["enum"],
  effects=["creates and removes HKCU/Software/LexeWorkload/Reg2-enum-<pid>"],
  expect={"REGISTRY_MODE": "enum", "REG_CREATE": "yes", "QUERY_INFO_KEY": "yes",
          "SUBKEY_COUNT": "3", "VALUE_COUNT": "3",
          "ENUM_KEYS_ENDED": "no-more-items",
          "ENUM_VALUES_ENDED": "no-more-items",
          "ENUM_SUBKEYS_SEEN": "3", "ENUM_VALUES_SEEN": "3",
          "ALL_THREE_SUBKEY_NAMES_FOUND": "yes",
          "ALL_THREE_VALUE_NAMES_FOUND": "yes",
          "SUBKEY_COUNT_MATCHES_WALK": "yes",
          "VALUE_COUNT_MATCHES_WALK": "yes", "CLEANED_UP": "yes"},
  caps=["a writable registry"],
  notes="Enumeration ORDER is not a contract, so the specimen checks the SET of "
        "names rather than the sequence, and separately checks that the count "
        "RegQueryInfoKeyW reported matches the number the walk actually produced -- "
        "a layer whose count and whose enumeration disagree is a real failure and "
        "would be invisible to either check alone. The key name carries the process "
        "id because one Wine prefix is shared by every specimen running at once.")
S("pe-registry-value-types", "w_registry2.c", "registry",
  "REG_BINARY, REG_MULTI_SZ, REG_EXPAND_SZ and REG_QWORD kept apart",
  argv=["types"],
  effects=["creates and removes HKCU/Software/LexeWorkload/Reg2-types-<pid>"],
  expect={"REGISTRY_MODE": "types", "REG_CREATE": "yes", "SET_BINARY": "yes",
          "SET_MULTI_SZ": "yes", "SET_EXPAND_SZ": "yes", "SET_QWORD": "yes",
          "QUERY_BINARY": "yes", "BINARY_TYPE_IS_REG_BINARY": "yes",
          "BINARY_SIZE": "8", "BINARY_HEX": "deadbeef00017f80",
          "BINARY_ROUNDTRIPPED": "yes", "QUERY_MULTI_SZ": "yes",
          "MULTI_SZ_TYPE_IS_REG_MULTI_SZ": "yes",
          "MULTI_SZ_STRING_COUNT": "3", "MULTI_SZ_FIRST_IS_ALPHA": "yes",
          "QUERY_EXPAND_SZ": "yes", "EXPAND_SZ_TYPE_IS_REG_EXPAND_SZ": "yes",
          "EXPAND_SZ_NOT_EXPANDED_BY_QUERY": "yes", "QUERY_QWORD": "yes",
          "QWORD_TYPE_IS_REG_QWORD": "yes", "QWORD_HEX": "0123456789abcdef",
          "QWORD_ROUNDTRIPPED": "yes", "CLEANED_UP": "yes"},
  caps=["a writable registry with typed values"],
  notes="A layer that collapses every value into REG_SZ passes "
        "pe-registry-roundtrip and fails here. The REG_EXPAND_SZ check is the "
        "subtle one: the API must NOT expand it, because expansion is the caller's "
        "job and a layer that helpfully expanded it would corrupt every installer "
        "path that contains a percent sign.")
S("pe-registry-absent", "w_registry2.c", "registry",
  "the registry error paths: absent key, absent value, buffer too small",
  argv=["absent"],
  expect={"REGISTRY_MODE": "absent", "OPEN_ABSENT_KEY": "fail",
          "OPEN_ABSENT_KEY_ERROR": "ERROR_FILE_NOT_FOUND",
          "ABSENT_KEY_REPORTED": "yes", "REG_CREATE": "yes",
          "QUERY_ABSENT_VALUE": "fail",
          "QUERY_ABSENT_VALUE_ERROR": "ERROR_FILE_NOT_FOUND",
          "QUERY_TOO_SMALL_ERROR": "ERROR_MORE_DATA",
          "TOO_SMALL_REPORTS_REQUIRED_SIZE": "yes",
          "DELETE_ABSENT_KEY": "fail",
          "DELETE_ABSENT_KEY_ERROR": "ERROR_FILE_NOT_FOUND",
          "SURVIVED_EVERY_ERROR_PATH": "yes"},
  notes="ERROR_MORE_DATA with the required size written back is how every caller "
        "grows its buffer; a layer that answered ERROR_FILE_NOT_FOUND there instead "
        "would make a present-but-large value look absent.")

# ---- threads and synchronisation, beyond mutex and event ------------------
S("pe-tls-both-mechanisms", "w_tls.c", "process",
  "TlsAlloc slots and compiler __thread, four threads, checked together",
  procbeh="multi-threaded",
  expect={"TLS_ALLOC": "yes", "BARRIER_EVENT": "yes", "THREADS_STARTED": "4",
          "TLS_API_PER_THREAD_OK": "4", "COMPILER_TLS_PER_THREAD_OK": "4",
          "TLS_API_ISOLATED_ALL_THREADS": "yes",
          "COMPILER_TLS_ISOLATED_ALL_THREADS": "yes",
          "MAIN_TLS_API_UNTOUCHED": "yes",
          "MAIN_COMPILER_TLS_UNTOUCHED": "yes", "TLS_FREE": "yes"},
  caps=["thread-local storage, both the API slots and the PE TLS directory"],
  notes="Two different mechanisms with different failure modes: TlsAlloc is a slot "
        "the program asks the OS for, __thread needs a TLS DIRECTORY in the PE that "
        "the loader sets up before any of this code runs. A runtime can get one "
        "right and the other wrong. Every thread WRITES before any thread READS, so "
        "a slot that is not really per-thread shows up as a mismatch rather than as "
        "a coincidence.")
S("pe-sync-semaphore", "w_semaphore.c", "process",
  "a counting semaphore, drained and probed at each known state",
  procbeh="multi-threaded",
  expect={"CREATE_SEMAPHORE": "yes", "INITIAL_COUNT": "2", "MAXIMUM_COUNT": "2",
          "TAKE_FIRST": "yes", "TAKE_SECOND": "yes", "PROBE_WHEN_EMPTY": "0",
          "EMPTY_SEMAPHORE_BLOCKS": "yes", "RELEASE_ONE": "yes",
          "PREVIOUS_COUNT_REPORTED": "0", "PREVIOUS_COUNT_WAS_ZERO": "yes",
          "PROBE_AFTER_RELEASE": "1", "RELEASED_SEMAPHORE_ADMITS_ONE": "yes",
          "RELEASE_PAST_MAXIMUM": "refused",
          "RELEASE_PAST_MAXIMUM_ERROR": "ERROR_TOO_MANY_POSTS",
          "OPEN_BY_NAME": "yes", "NAMED_OBJECT_IS_SHARED": "yes"},
  caps=["named kernel objects"],
  notes="Testing a semaphore by racing N threads at it is a race dressed up as a "
        "test. This drains it from the main thread so the state is known exactly at "
        "every step, and a probe thread reports what a zero-timeout wait sees at "
        "each of those states. Releasing past the maximum has its own distinct "
        "error, which is what tells a caller it has a bookkeeping bug rather than a "
        "busy resource.")
S("pe-sync-wait-multiple", "w_waitmulti.c", "process",
  "WaitForMultipleObjects: the index, the timeout, and bWaitAll",
  procbeh="single-process",
  expect={"EVENTS_CREATED": "yes", "OBJECT_COUNT": "4",
          "WAIT_NONE_SIGNALLED": "timeout", "IDLE_WAIT_TIMED_OUT": "yes",
          "SIGNALLED_INDEX": "2", "CORRECT_INDEX_REPORTED": "yes",
          "LOWEST_OF_TWO_INDEX": "1", "LOWEST_INDEX_WINS": "yes",
          "HIGHER_INDEX_NOT_CONSUMED": "yes", "WAIT_ALL": "signalled",
          "WAIT_ALL_SUCCEEDED": "yes", "WAIT_ALL_CONSUMED_EVERY_OBJECT": "yes"},
  notes="The two easy-to-get-wrong parts are asserted explicitly: with two objects "
        "signalled the call must return the LOWEST index, and it must consume ONLY "
        "that one, so the auto-reset event at the higher index is still signalled "
        "afterwards. An implementation that returned an arbitrary ready object, or "
        "consumed both, passes a naive test and fails this one.")
S("pe-sync-interlocked", "w_interlocked.c", "process",
  "eight threads on three atomic primitives, with exact totals",
  procbeh="multi-threaded", timeout=180.0,
  expect={"THREADS": "8", "ITERATIONS_EACH": "50000", "THREADS_STARTED": "8",
          "INCREMENT_TOTAL": "400000", "ADD_TOTAL": "1200000",
          "CAS_GUARDED_TOTAL": "400000", "EXCHANGE_COUNT": "400000",
          "SPIN_LOCK_RELEASED": "0", "ALL_THREADS_STARTED": "yes",
          "INCREMENT_WAS_ATOMIC": "yes", "EXCHANGE_ADD_WAS_ATOMIC": "yes",
          "COMPARE_EXCHANGE_MUTUAL_EXCLUSION": "yes",
          "LOCK_NOT_LEFT_HELD": "yes"},
  caps=["atomic read-modify-write across cores"],
  notes="One of the very few specimens where an exact number is a CORRECTNESS claim "
        "rather than a description: if an Interlocked operation is not really "
        "atomic the totals come out LOW, and by how much is the race. Deliberately "
        "32-bit LONG throughout so the same source means the same thing in a "
        "WoW64 process.")
S("pe-sync-condition-variable", "w_condvar.c", "process",
  "SRWLOCK and CONDITION_VARIABLE over a ring smaller than the workload",
  procbeh="multi-threaded", timeout=180.0,
  expect={"RING_CAPACITY": "4", "ITEMS": "100", "PRODUCER_THREAD": "yes",
          "PRODUCED": "100", "CONSUMED": "100", "CONSUMED_SUM": "4950",
          "RING_DRAINED": "0", "EVERY_ITEM_PRODUCED": "yes",
          "EVERY_ITEM_CONSUMED": "yes", "NO_ITEM_LOST_OR_DUPLICATED": "yes",
          "RING_EMPTY_AT_END": "yes", "PRODUCER_REALLY_BLOCKED": "yes",
          "CONSUMER_REALLY_BLOCKED": "yes", "SHARED_READERS_CONCURRENT": "4",
          "SRWLOCK_SHARED_ADMITS_ALL_FOUR": "yes"},
  caps=["SRWLOCK and CONDITION_VARIABLE"],
  notes="Not kernel objects with handles: structures the runtime manipulates in the "
        "process's own memory, so a translation layer has to provide them itself. "
        "The two blocking claims are forced rather than hoped for -- the consumer "
        "waits 150 ms before its first take so the producer MUST fill the ring, and "
        "the producer paces itself after the eighth item so the consumer MUST run it "
        "dry. Without that, PRODUCER_REALLY_BLOCKED would be a race that usually "
        "happened to pass, and the exact totals would prove much less than they "
        "look.")
S("pe-proc-fibers", "w_fiber.c", "process",
  "cooperative fibers switching in a fixed order inside one thread",
  procbeh="single-process",
  expect={"CONVERT_THREAD_TO_FIBER": "yes", "CREATE_FIBER_A": "yes",
          "CREATE_FIBER_B": "yes", "FIBER_SEQUENCE": "mAmBmAm",
          "FIBER_A_ENTRIES": "2", "FIBER_B_ENTRIES": "1",
          "SWITCHING_ORDER_AS_PROGRAMMED": "yes",
          "FIBER_A_RESUMED_NOT_RESTARTED": "yes",
          "ALL_FIBERS_ON_ONE_THREAD": "yes",
          "CONVERT_FIBER_TO_THREAD": "yes"},
  caps=["fibers"],
  notes="Real Windows games use fibers: a job system built on them is a standard "
        "engine design. They are also the one place a translation layer must "
        "reproduce a CONTEXT SWITCH it performs itself, stack and all. Fiber A is "
        "entered twice and must RESUME the second time rather than restart, which "
        "is the difference between a real fiber and a callback.")
S("pe-proc-apc", "w_apc.c", "process",
  "an APC queued onto another thread, delivered by an alertable wait",
  procbeh="multi-threaded", timeout=180.0,
  expect={"READY_EVENT": "yes", "WORKER_THREAD": "yes",
          "WORKER_REACHED_SLEEP": "yes", "QUEUE_USER_APC": "yes",
          "APC_RAN_COUNT": "1", "APC_ARGUMENT_HEX": "5afe",
          "SLEEPEX_RETURN": "192",
          "APC_RAN_DURING_NON_ALERTABLE_SLEEP": "no",
          "APC_RAN_EXACTLY_ONCE": "yes", "APC_ARGUMENT_DELIVERED": "yes",
          "APC_RAN_ON_THE_TARGET_THREAD": "yes",
          "SLEEPEX_RETURNED_IO_COMPLETION": "yes",
          "ALERTABLE_WAIT_ENDED_EARLY": "yes",
          "NON_ALERTABLE_SLEEP_DID_NOT_RUN_IT": "yes"},
  caps=["user-mode APCs"],
  notes="There is no POSIX equivalent worth leaning on. The ordering is not a race: "
        "an APC queued to a thread that is not yet alertable is delivered as soon as "
        "it becomes alertable, so both interleavings give the same answer. The "
        "negative half is the interesting one -- the same APC must NOT run during "
        "the worker's NON-alertable sleep, which is what makes 'alertable' mean "
        "something. 192 is WAIT_IO_COMPLETION.")
S("pe-proc-suspended-thread", "w_suspend.c", "process",
  "CREATE_SUSPENDED and the nesting suspend COUNT",
  procbeh="multi-threaded", timeout=180.0,
  expect={"CREATE_SUSPENDED": "yes", "PHASE_WHILE_SUSPENDED": "0",
          "DID_NOT_RUN_WHILE_SUSPENDED": "yes",
          "FIRST_RESUME_PREVIOUS_COUNT": "1",
          "FIRST_RESUME_REPORTED_COUNT_ONE": "yes", "RAN_AFTER_RESUME": "yes",
          "SUSPEND_ONE_PREVIOUS_COUNT": "0", "SUSPEND_TWO_PREVIOUS_COUNT": "1",
          "SUSPEND_COUNT_NESTS": "yes",
          "RESUME_FROM_TWO_PREVIOUS_COUNT": "2",
          "RESUME_FROM_TWO_REPORTED_TWO": "yes",
          "STILL_SUSPENDED_AFTER_ONE_RESUME": "yes",
          "FINAL_RESUME_PREVIOUS_COUNT": "1", "FINAL_RESUME_REPORTED_ONE": "yes",
          "THREAD_JOINED": "yes", "FINAL_PHASE": "3", "THREAD_COMPLETED": "yes",
          "MADE_PROGRESS_AFTER_FULL_RESUME": "yes",
          "GET_EXIT_CODE_THREAD": "yes", "THREAD_EXIT_CODE": "0"},
  caps=["suspended thread creation and nested suspend counts"],
  notes="Creating a thread suspended is how real software sets one up -- priority, "
        "affinity, an injected hook -- before it can run an instruction. The COUNT "
        "is the part that matters: suspends nest, so a thread suspended twice needs "
        "resuming twice, and a runtime that treats suspend as a boolean lets a "
        "thread run one resume too early.")

# ---- memory and exception handling ---------------------------------------
S("pe-mem-virtual-states", "w_virtualalloc.c", "memory",
  "reserve, commit, protect, decommit, release, each verified by VirtualQuery",
  argv=["states"],
  expect={"VIRTUAL_MODE": "states", "RESERVE": "yes",
          "AFTER_RESERVE_QUERY": "ok", "AFTER_RESERVE_STATE": "MEM_RESERVE",
          "AFTER_RESERVE_REGION_SIZE": "65536", "COMMIT": "yes",
          "AFTER_COMMIT_STATE": "MEM_COMMIT",
          "AFTER_COMMIT_PROTECT": "PAGE_READWRITE",
          "COMMITTED_PAGE_IS_WRITABLE": "yes",
          "REST_OF_REGION_STATE": "MEM_RESERVE", "PROTECT_READONLY": "yes",
          "PROTECT_PREVIOUS": "PAGE_READWRITE", "PREVIOUS_WAS_READWRITE": "yes",
          "AFTER_PROTECT_PROTECT": "PAGE_READONLY",
          "READONLY_PAGE_STILL_READABLE": "yes", "DECOMMIT": "yes",
          "AFTER_DECOMMIT_STATE": "MEM_RESERVE", "RELEASE": "yes",
          "AFTER_RELEASE_STATE": "MEM_FREE", "RELEASE_WITH_SIZE": "refused",
          "RELEASE_WITH_SIZE_ERROR": "ERROR_INVALID_PARAMETER"},
  caps=["VirtualAlloc reserve/commit semantics"],
  notes="The reserve/commit distinction has no POSIX equivalent of quite this "
        "shape, and a layer that treats them as the same thing passes every simple "
        "allocation test and then falls over on a program that reserves a large "
        "region and commits it a page at a time -- which is what a game's streaming "
        "allocator does. REST_OF_REGION_STATE is the check that catches it: after "
        "committing ONE page of a 64 KiB reservation the rest must still say "
        "MEM_RESERVE.")
S("pe-mem-noaccess-page-faults", "w_virtualalloc.c", "memory",
  "PAGE_NOACCESS really enforced, and the fault caught and converted",
  argv=["noaccess"], exit=12,
  expect={"VIRTUAL_MODE": "noaccess", "COMMIT": "yes",
          "WRITABLE_WHILE_READWRITE": "yes", "PROTECT_NOACCESS": "yes",
          "PREVIOUS_PROTECTION": "PAGE_READWRITE",
          "AFTER_NOACCESS_PROTECT": "PAGE_NOACCESS",
          "DELIBERATE_FAULT": "write-to-PAGE_NOACCESS",
          "WORK_BEFORE_FAULT": "done", "FAULT_CODE": "0xc0000005",
          "FAULT_WAS_ACCESS_VIOLATION": "yes", "FAULT_WAS_A_WRITE": "yes",
          "PROTECTION_WAS_ENFORCED": "yes",
          "NOACCESS_PAGE_REALLY_FAULTED": "yes"},
  expect_absent=["FAULT_DID_NOT_HAPPEN"],
  notes="Memory protection that is NOT enforced would be invisible to the `states` "
        "specimen: VirtualQuery would happily report PAGE_NOACCESS while the page "
        "stayed writable. This writes to it. The fault is caught by a top-level "
        "filter which reports the code, says whether it was a read or a write, and "
        "exits 12 -- so the declared outcome is a clean exit 12 with a complete "
        "oracle, not a crash.")
S("pe-exception-unhandled-filter", "w_exception.c", "outcome",
  "a crash converted into a chosen exit code by a top-level filter",
  argv=["filter"], exit=9,
  expect={"EXCEPTION_MODE": "filter", "SET_UNHANDLED_EXCEPTION_FILTER": "yes",
          "DELIBERATE_FAULT": "access-violation-to-be-handled",
          "WORK_BEFORE_FAULT": "done", "FILTER_RAN": "yes",
          "FILTER_CODE": "0xc0000005",
          "FILTER_SAW_ACCESS_VIOLATION": "yes",
          "FILTER_HAS_FAULT_ADDRESS": "yes",
          "VEH_RAN_BEFORE_THE_FILTER": "no",
          "HANDLER_CHOSE_EXIT_CODE": "9",
          "CRASH_WAS_HANDLED_NOT_FATAL": "yes"},
  expect_absent=["FAULT_DID_NOT_HAPPEN"],
  notes="This is the machinery every Windows crash reporter is built on, and the "
        "difference between a program that dies and one that dies TIDILY. "
        "Deliberately NOT tagged EXPECT_DEATH: the fault happens, but the process "
        "does not die of it -- the filter writes its report and ends the process "
        "itself with a status of its own choosing. A layer that never ran the "
        "filter would produce a raw access violation instead of exit 9, and the "
        "difference is exactly what a crash reporter cares about.")
S("pe-exception-vectored-ordering", "w_exception.c", "outcome",
  "a vectored handler runs BEFORE the top-level filter",
  argv=["vectored"], exit=9,
  expect={"EXCEPTION_MODE": "vectored", "ADD_VECTORED_HANDLER": "yes",
          "VEH_SAW_EXCEPTION": "yes", "VEH_CODE": "0xc0000005",
          "VEH_FILTER_HAD_ALREADY_RUN": "no", "FILTER_RAN": "yes",
          "VEH_RAN_BEFORE_THE_FILTER": "yes",
          "CRASH_WAS_HANDLED_NOT_FATAL": "yes"},
  notes="The ORDER is the property. Vectored handlers see an exception before any "
        "frame-based handling and before the unhandled-exception filter; a layer "
        "that ran them in the other order would break every anti-cheat, profiler "
        "and crash reporter that installs one to get first refusal.")
S("pe-exception-continue-execution", "w_exception.c", "outcome",
  "an exception fully recovered from: RaiseException RETURNS and the run continues",
  argv=["continue"], exit=0,
  expect={"EXCEPTION_MODE": "continue", "ADD_VECTORED_HANDLER": "yes",
          "ABOUT_TO_RAISE": "0xE0000099", "VEH_SAW_EXCEPTION": "yes",
          "VEH_CODE": "0xe0000099", "VEH_DECISION": "continue-execution",
          "RAISE_RETURNED": "yes", "VEH_HITS": "1",
          "EXCEPTION_FULLY_RECOVERED": "yes",
          "EXECUTION_RESUMED_AFTER_THE_HANDLER": "yes"},
  notes="The one case in the corpus where an exception is recovered from completely "
        "and the program goes on to exit 0 normally. The exception is raised WITHOUT "
        "EXCEPTION_NONCONTINUABLE, so continuing is legitimate -- which is precisely "
        "the distinction pe-outcome-abnormal-raise exists to show the other side "
        "of, where the system Wine continues from a NONCONTINUABLE one and should "
        "not.")

# ---- the filesystem, the Windows-specific parts ---------------------------
S("pe-fs-sharing-mode", "w_fileshare.c", "filesystem",
  "share modes enforced by the kernel, with no POSIX equivalent behind them",
  effects=["creates and removes shared.dat"],
  expect={"CREATE_EXCLUSIVE": "yes",
          "SECOND_OPEN_WHILE_EXCLUSIVE": "refused",
          "SECOND_OPEN_WHILE_EXCLUSIVE_ERROR": "ERROR_SHARING_VIOLATION",
          "DELETE_WHILE_OPEN": "refused",
          "DELETE_WHILE_OPEN_ERROR": "ERROR_SHARING_VIOLATION",
          "REOPEN_SHARING_READ": "yes", "READER_WHILE_SHARE_READ": "opened",
          "READER_WITH_INCOMPATIBLE_SHARE": "refused",
          "READER_WITH_INCOMPATIBLE_SHARE_ERROR": "ERROR_SHARING_VIOLATION",
          "WRITER_WHILE_SHARE_READ": "refused",
          "WRITER_WHILE_SHARE_READ_ERROR": "ERROR_SHARING_VIOLATION",
          "READER_AFTER_CLOSE": "opened", "WRITER_AFTER_CLOSE": "opened",
          "DELETE_AFTER_CLOSE": "yes", "GONE": "yes"},
  caps=["kernel-enforced file sharing modes"],
  notes="On Windows the sharing mode is declared at open time and the KERNEL "
        "refuses a conflicting second open; on Unix nothing of the sort happens by "
        "default, so a layer has to provide this itself. It is also why Windows "
        "installers reboot and Unix ones do not: DeleteFileW on a file with an open "
        "handle and no FILE_SHARE_DELETE must fail. FIXTURE BUG FOUND BY ITS OWN "
        "BASELINE: the first version asked for FILE_SHARE_READ alone as the reader "
        "and declared 'opened'; it got 'refused', and the layer was right. The check "
        "is SYMMETRIC -- a reader demanding FILE_SHARE_READ only is saying nobody "
        "may write, while a writer already holds the file. The C source was fixed "
        "to permit the writer, and the wrong case was KEPT as "
        "READER_WITH_INCOMPATIBLE_SHARE, because a layer that enforced only the "
        "existing handle's share mode and not the new opener's would pass the "
        "corrected check and fail this one.")
S("pe-fs-file-attributes", "w_fileattrs.c", "filesystem",
  "READONLY and HIDDEN, and READONLY blocking deletion",
  effects=["creates and removes attrs.dat"],
  expect={"CREATE": "yes", "FRESH_READONLY": "no", "SET_READONLY": "yes",
          "AFTER_READONLY_READONLY": "yes",
          "OPEN_READONLY_FOR_WRITE": "refused",
          "OPEN_READONLY_FOR_WRITE_ERROR": "ERROR_ACCESS_DENIED",
          "DELETE_READONLY": "refused",
          "DELETE_READONLY_ERROR": "ERROR_ACCESS_DENIED",
          "READ_READONLY": "yes", "READONLY_CONTENT_INTACT": "yes",
          "SET_HIDDEN": "yes", "AFTER_HIDDEN_HIDDEN": "yes",
          "AFTER_HIDDEN_READONLY": "no", "HIDDEN_STILL_OPENABLE": "yes",
          "CLEAR_ATTRS": "yes", "AFTER_CLEAR_READONLY": "no",
          "AFTER_CLEAR_HIDDEN": "no", "DELETE_AFTER_CLEAR": "yes",
          "GONE": "yes", "ATTRS_OF_ABSENT_FILE": "invalid",
          "ATTRS_OF_ABSENT_FILE_ERROR": "ERROR_FILE_NOT_FOUND"},
  caps=["DOS file attributes stored and honoured"],
  notes="These are Windows attributes with no Unix mode bit behind them, so a layer "
        "has to keep them somewhere -- an extended attribute, usually. An installer "
        "that marks a file read-only and then cannot delete it is depending on the "
        "answer being the real one.")
S("pe-fs-directory-operations", "w_dirops.c", "filesystem",
  "the directory error paths, including 'wrong kind of object'",
  effects=["creates and removes dirops/ and its contents"],
  expect={"CREATE_DIRECTORY": "yes", "IS_A_DIRECTORY": "yes",
          "CREATE_EXISTING_DIRECTORY": "refused",
          "CREATE_EXISTING_DIRECTORY_ERROR": "ERROR_ALREADY_EXISTS",
          "CREATE_WITH_MISSING_PARENT": "refused",
          "CREATE_WITH_MISSING_PARENT_ERROR": "ERROR_PATH_NOT_FOUND",
          "CREATE_NESTED": "yes", "CREATE_FILE_INSIDE": "yes",
          "REMOVE_NON_EMPTY_DIRECTORY": "refused",
          "REMOVE_NON_EMPTY_DIRECTORY_ERROR": "ERROR_DIR_NOT_EMPTY",
          "REMOVE_DIRECTORY_ON_A_FILE": "refused",
          "DELETE_FILE_ON_A_DIRECTORY": "refused",
          "GET_CURRENT_DIRECTORY": "yes", "SET_CURRENT_DIRECTORY": "yes",
          "CWD_ENDS_IN_NESTED": "yes",
          "PARENT_FILE_VISIBLE_FROM_CHILD_DIR": "no",
          "PARENT_FILE_VISIBLE_VIA_DOTDOT": "yes",
          "RETURN_TO_ORIGINAL_DIRECTORY": "yes", "DELETE_INSIDE_FILE": "yes",
          "REMOVE_NESTED": "yes", "REMOVE_NOW_EMPTY_DIRECTORY": "yes",
          "DIRECTORY_GONE": "yes"},
  notes="w_dirtree.c walks a tree that exists; this one asks what happens when it "
        "does not, or is the wrong kind of thing. The 'wrong kind of object' "
        "refusals are how an uninstaller decides whether what it is about to remove "
        "is a file or a directory, and a layer that answered ERROR_ACCESS_DENIED to "
        "all of them would make that undecidable. WHICH error those two produce is "
        "recorded rather than declared: only that they are refused is a property of "
        "the program. SetCurrentDirectoryW is checked by the RELATIONSHIP between "
        "the two paths, never by the paths themselves, which are environmental.")
S("pe-fs-memory-mapped-file", "w_memmap.c", "filesystem",
  "a file written THROUGH a mapping, and a named section shared in-process",
  effects=["creates and removes mapped.dat"],
  expect={"CREATE_FILE": "yes", "CREATE_FILE_MAPPING": "yes",
          "MAPPING_SIZE": "4096", "MAP_VIEW_OF_FILE": "yes",
          "VIEW_HASH": "e617258064ad8325", "FLUSH_VIEW": "yes",
          "UNMAP_VIEW": "yes", "MAP_VIEW_READ_ONLY": "yes",
          "READ_ONLY_VIEW_HASH": "e617258064ad8325",
          "READ_ONLY_VIEW_SEES_THE_WRITES": "yes", "SEEK_TO_START": "yes",
          "READ_FILE": "yes", "READ_BYTES": "4096",
          "FILE_HASH": "e617258064ad8325",
          "FILE_ON_DISK_MATCHES_THE_VIEW": "yes",
          "CREATE_NAMED_SECTION": "yes",
          "OPEN_NAMED_SECTION_BY_NAME": "yes", "BOTH_VIEWS_MAPPED": "yes",
          "SECOND_HANDLE_SEES_THE_SAME_MEMORY": "yes",
          "OPEN_ABSENT_SECTION": "refused",
          "OPEN_ABSENT_SECTION_ERROR": "ERROR_FILE_NOT_FOUND",
          "DELETE_MAPPED_FILE": "yes"},
  caps=["file mappings and named section objects"],
  notes="Games map their asset archives rather than reading them, and a mapping is "
        "the one file API where the data path bypasses ReadFile entirely -- so a "
        "layer can have perfect ReadFile behaviour and still get this wrong. The "
        "hash is declared from the pattern the program writes, computed before "
        "running, and the same value must come back three ways: through the "
        "writable view, through a second read-only view, and through an ordinary "
        "ReadFile from disk.")
S("pe-fs-case-insensitive", "w_casefold.c", "filesystem",
  "case-insensitive lookup with case-preserving storage",
  effects=["creates and removes MixedCase.TXT"],
  expect={"CREATE_MIXED_CASE": "yes", "OPEN_ALL_LOWER": "opened",
          "LOWERCASE_NAME_RESOLVED": "yes", "OPEN_ALL_UPPER": "opened",
          "UPPERCASE_NAME_RESOLVED": "yes", "EXACT_NAME_RESOLVED": "yes",
          "FOUND_BY_UPPERCASE_PATTERN": "yes", "FOUND_NAME_LEN": "13",
          "FOUND_NAME_HEX": "4d69786564436173652e545854",
          "CASE_WAS_PRESERVED_ON_DISK": "yes",
          "ATTRS_BY_LOWER_NAME": "found", "ATTRIBUTES_FOLDED_TOO": "yes",
          "CREATE_ALWAYS_OTHER_CASE": "yes", "TXT_FILES_PRESENT": "1",
          "NO_SECOND_FILE_WAS_CREATED": "yes", "DELETE_BY_LOWER_NAME": "yes",
          "GONE": "yes"},
  caps=["case-insensitive, case-preserving filenames"],
  notes="The single biggest behavioural gap between a Windows filesystem and the "
        "Linux one a translation layer sits on, and an enormous amount of real "
        "Windows software depends on it: write Save.DAT, read save.dat. Both halves "
        "are checked -- the folding AND the preservation -- because a "
        "lowercase-everything implementation gets the first right and the second "
        "wrong. NO_SECOND_FILE_WAS_CREATED is the one that catches a layer folding "
        "in CreateFile but not in the directory itself.")
S("pe-fs-file-times", "w_filetimes.c", "filesystem",
  "an exact FILETIME set, read back, and converted to a SYSTEMTIME",
  effects=["creates and removes times.dat"],
  expect={"CREATE": "yes", "REQUESTED_FILETIME_HEX": "01c0000000000001",
          "SET_FILE_TIME": "yes", "GET_FILE_TIME": "yes",
          "MODIFIED_FILETIME_HEX": "01c0000000000001",
          "MODIFIED_TIME_ROUNDTRIPPED_EXACTLY": "yes",
          "FILETIME_RESOLUTION_NOT_LOST_TO_SECONDS": "yes",
          "FILETIME_TO_SYSTEMTIME": "yes",
          "SYSTEMTIME": "2000-08-06T23:42:36.637Z",
          "SYSTEMTIME_TO_FILETIME": "yes",
          "ROUNDTRIP_TICK_DIFFERENCE": "3889", "REOPEN": "yes",
          "MODIFIED_AFTER_REOPEN_HEX": "01c0000000000001",
          "TIME_PERSISTED_TO_DISK": "yes",
          "GET_FILE_ATTRIBUTES_EX": "yes",
          "BY_NAME_MODIFIED_HEX": "01c0000000000001",
          "BY_NAME_SIZE_LOW": "5",
          "BY_NAME_AGREES_WITH_BY_HANDLE": "yes", "DELETE": "yes"},
  caps=["100-nanosecond file timestamps"],
  notes="A FILETIME is 100-ns ticks since 1601 and a Unix timestamp is seconds since "
        "1970, so a layer has to convert, and the two places it goes wrong are the "
        "EPOCH and the RESOLUTION. The value chosen is deliberately one tick past a "
        "round number: a layer storing whole seconds loses the low digits and a "
        "layer with the wrong epoch reports a different year. 2000-08-06T23:42:36"
        ".637Z and the 3889-tick SYSTEMTIME round-trip loss were both computed from "
        "the definition of a FILETIME before the specimen was ever run. The CREATION "
        "time is deliberately NOT declared -- whether a birth time can be set at all "
        "is a property of the underlying filesystem, not of Windows.")
S("pe-fs-file-position", "w_filepos.c", "filesystem",
  "SetFilePointerEx, SetEndOfFile, and what an extended file contains",
  effects=["creates and removes positions.dat"],
  expect={"CREATE": "yes", "WRITE_100": "yes", "SIZE_AFTER_WRITE": "100",
          "POSITION_AFTER_WRITE": "100", "SEEK_FROM_BEGIN_10": "10",
          "SEEK_RELATIVE_PLUS_5": "15", "SEEK_FROM_END_MINUS_10": "90",
          "SEEK_PAST_END_TO_500": "500",
          "SIZE_UNCHANGED_BY_SEEK_PAST_END": "100",
          "SEEK_PAST_END_DOES_NOT_GROW_THE_FILE": "yes",
          "SET_END_OF_FILE_TRUNCATE": "yes", "SIZE_AFTER_TRUNCATE": "50",
          "TRUNCATED_TO_50": "yes", "SET_END_OF_FILE_EXTEND": "yes",
          "SIZE_AFTER_EXTEND": "200", "EXTENDED_TO_200": "yes",
          "READ_BACK": "yes", "READ_BYTES": "200",
          "SURVIVING_PAYLOAD_BYTES": "50", "ZERO_FILLED_GAP_BYTES": "150",
          "READ_STOPPED_AT_END_OF_FILE": "yes",
          "FIRST_50_BYTES_UNCHANGED": "yes",
          "EXTENSION_READS_AS_ZEROS": "yes", "WRITE_AT_300": "yes",
          "SIZE_AFTER_TAIL_WRITE": "304", "FILE_GREW_TO_304": "yes",
          "HOLE_BEFORE_TAIL_IS_ZEROS": "yes",
          "TAIL_IS_WHERE_IT_WAS_PUT": "yes",
          "READ_AT_EOF_SUCCEEDED": "yes", "READ_AT_EOF_BYTES": "0",
          "READ_AT_EOF_RETURNS_ZERO_BYTES": "yes", "DELETE": "yes"},
  notes="Every number here is an offset into the specimen's OWN data file, which "
        "carries nothing but this payload -- never a stream that also carries "
        "FIXTURE_ID. A layer that seeks the host file and forgets SetEndOfFile "
        "leaves the file SHORT, and nothing notices until something reads it back; "
        "that is what the two size assertions and the zero-fill counts are for.")
S("pe-fs-copy-and-move", "w_copymove.c", "filesystem",
  "CopyFileW and MoveFileExW, including the refusals a patcher branches on",
  effects=["creates and removes src.dat, dst.dat and moved.dat"],
  expect={"WRITE_SOURCE": "yes", "WRITE_TARGET": "yes",
          "COPY_FAIL_IF_EXISTS": "refused",
          "COPY_FAIL_IF_EXISTS_ERROR": "ERROR_FILE_EXISTS",
          "TARGET_AFTER_REFUSED_COPY": "TARGET-V0",
          "REFUSED_COPY_LEFT_TARGET_ALONE": "yes", "COPY_OVERWRITING": "yes",
          "TARGET_AFTER_COPY": "SOURCE-V1",
          "COPY_REPLACED_THE_CONTENT": "yes",
          "COPY_LEFT_SOURCE_IN_PLACE": "yes",
          "MOVE_ONTO_EXISTING": "refused",
          "MOVE_ONTO_EXISTING_ERROR": "ERROR_ALREADY_EXISTS",
          "REFUSED_MOVE_LEFT_SOURCE_IN_PLACE": "yes",
          "WRITE_SOURCE_V2": "yes", "MOVE_EX_REPLACE_EXISTING": "yes",
          "TARGET_AFTER_REPLACE": "SOURCE-V2",
          "REPLACE_MOVED_THE_CONTENT": "yes",
          "MOVE_CONSUMED_THE_SOURCE": "yes",
          "PLAIN_MOVE_TO_A_FREE_NAME": "yes", "OLD_NAME_GONE": "yes",
          "CONTENT_SURVIVED_THE_MOVE": "yes", "MOVE_ABSENT_SOURCE": "refused",
          "MOVE_ABSENT_SOURCE_ERROR": "ERROR_FILE_NOT_FOUND",
          "COPY_ABSENT_SOURCE": "refused",
          "COPY_ABSENT_SOURCE_ERROR": "ERROR_FILE_NOT_FOUND",
          "CLEANUP": "yes"},
  notes="The two move failures have DIFFERENT errors and that difference is what a "
        "patcher branches on: ERROR_ALREADY_EXISTS means 'add the replace flag', "
        "ERROR_FILE_NOT_FOUND means 'my download is missing'. A layer answering "
        "ERROR_ACCESS_DENIED to both makes them indistinguishable. The refused copy "
        "is also checked for having left the target's CONTENT alone, not merely for "
        "having returned false.")
S("pe-fs-deep-and-long-paths", "w_deeppath.c", "filesystem",
  "a deep path under MAX_PATH, and a long one over it through the \\\\?\\ prefix",
  timeout=180.0,
  effects=["creates a twelve-level directory tree and a long-path tree"],
  expect={"DEEP_DEPTH_REQUESTED": "12", "DEEP_RELATIVE_LENGTH": "208",
          "CREATED_EVERY_LEVEL": "yes", "CREATE_FILE_AT_DEPTH": "yes",
          "REOPEN_FILE_AT_DEPTH": "yes", "DEEP_CONTENT_MATCHES": "yes",
          "DELETE_FILE_AT_DEPTH": "yes", "LONG_PATH_ATTEMPTED": "yes",
          "LONG_PATH_EXCEEDS_MAX_PATH": "yes",
          "SURVIVED_BOTH_PATH_LENGTHS": "yes"},
  expect_one_of={"LONG_PATH_WITH_PREFIX": ["created", "refused"],
                 "LONG_PATH_WITHOUT_PREFIX": ["created", "refused"]},
  notes="Two different things, deliberately kept apart. The DEEP tree is still "
        "shorter than MAX_PATH and must work everywhere, so it is declared exactly. "
        "Whether a path LONGER than 260 works through the \\\\?\\ prefix depends on "
        "the filesystem underneath and on how much of the \\\\?\\ handling the layer "
        "implements -- a platform choice, so expect_one_of. What is NOT optional is "
        "that the program survives either answer and says which happened.")
S("pe-fs-overlapped-io", "w_overlapped.c", "filesystem",
  "asynchronous file I/O where the OVERLAPPED offset, not the file pointer, decides",
  effects=["creates and removes overlapped.dat"],
  expect={"CREATE_OVERLAPPED": "yes", "MIDDLE_RESULT": "ok",
          "MIDDLE_BYTES": "8", "FIRST_RESULT": "ok", "FIRST_BYTES": "8",
          "LAST_RESULT": "ok", "LAST_BYTES": "8", "WRITE_MIDDLE": "yes",
          "WRITE_FIRST": "yes", "WRITE_LAST": "yes",
          "OVERLAPPED_READ": "yes", "READ_BYTES": "40",
          "READ_WHOLE_FILE": "yes", "FIRST_AT_OFFSET_0": "yes",
          "MIDDLE_AT_OFFSET_16": "yes", "LAST_AT_OFFSET_32": "yes",
          "GAPS_ARE_ZEROS": "yes", "FILE_HASH": "a17577f550c48849",
          "DELETE": "yes"},
  caps=["FILE_FLAG_OVERLAPPED"],
  notes="With FILE_FLAG_OVERLAPPED the file pointer is IGNORED and the offset in "
        "the OVERLAPPED is the only thing that decides where the bytes go -- so the "
        "three writes are issued OUT OF ORDER and the resulting file is checked byte "
        "for byte. A layer that quietly used the file pointer instead would write "
        "them sequentially and the hash would be wrong. Whether each call completes "
        "immediately or reports ERROR_IO_PENDING is a platform choice and is "
        "recorded, not declared.")

# ---- process spawning outside the tree -----------------------------------
S("pe-proc-self-spawn-redirect", "w_selfspawn.c", "process",
  "a process spawning ITSELF with both streams redirected to files",
  procbeh="parent-and-child", oracle_file="w_selfspawn_parent.oracle",
  timeout=180.0,
  effects=["creates child_stdout.txt, child_stderr.txt and the child's oracle"],
  expect={"ROLE": "parent", "SELF_PATH": "yes",
          "OPENED_CHILD_STDOUT_FILE": "yes",
          "OPENED_CHILD_STDERR_FILE": "yes", "SPAWNED_SELF": "yes",
          "WAITED_FOR_CHILD": "yes", "CHILD_EXIT_DECIMAL": "7",
          "CHILD_EXIT_WAS_SEVEN": "yes",
          "CHILD_STDOUT_REACHED_THE_FILE": "yes",
          "CHILD_STDERR_REACHED_THE_FILE": "yes",
          "STREAMS_WERE_NOT_CROSSED": "yes",
          "CHILD_LEFT_ITS_OWN_ORACLE": "yes"},
  post={"w_selfspawn_child.oracle": ["ROLE=child",
                                     "CHILD_WROTE_BOTH_STREAMS=yes",
                                     "RESULT=PASS"],
        "child_stdout.txt": ["CHILD_STDOUT_MARKER=yes"],
        "child_stderr.txt": ["CHILD_STDERR_MARKER=yes"]},
  caps=["handle inheritance into a child process"],
  notes="One binary, two roles by argv, so there is no second executable to stage "
        "and no chance of the two halves drifting apart -- and real Windows software "
        "re-invokes itself constantly. STREAMS_WERE_NOT_CROSSED is the assertion "
        "that a single combined redirect would fail: the stderr marker must NOT be "
        "in the stdout file.")
S("pe-proc-job-object", "w_jobobject.c", "process",
  "a job object owning a child, and TerminateJobObject with a chosen status",
  procbeh="parent-and-child", oracle_file="w_jobobject_parent.oracle",
  timeout=180.0,
  effects=["creates job_child_alive.flag and the child's truncated oracle"],
  expect={"ROLE": "parent", "SELF_PATH": "yes", "CREATE_JOB_OBJECT": "yes",
          "OPEN_JOB_BY_NAME": "yes", "SPAWNED_SUSPENDED_CHILD": "yes",
          "ASSIGN_PROCESS_TO_JOB": "yes", "CHILD_IS_IN_THE_JOB": "yes",
          "RESUMED_CHILD": "yes", "CHILD_REPORTED_ALIVE_BEFORE_KILL": "yes",
          "TERMINATE_JOB_OBJECT": "yes", "CHILD_DIED_PROMPTLY": "yes",
          "CHILD_EXIT_DECIMAL": "55", "CHILD_EXIT_HEX": "0x00000037",
          "JOB_STATUS_BECAME_THE_CHILD_EXIT_CODE": "yes",
          "CHILD_ORACLE_EXISTS": "yes", "CHILD_GOT_AS_FAR_AS_ALIVE": "yes",
          "CHILD_NEVER_COMPLETED": "yes", "CHILD_WROTE_NO_RESULT": "yes"},
  post={"w_jobobject_child.oracle": ["ROLE=child", "CHILD_ALIVE=yes"]},
  caps=["job objects"],
  notes="Job objects are how Windows makes 'the application and everything it "
        "started' a real, enforceable set rather than something a supervisor has to "
        "guess from parent pids -- which is exactly the problem the process-tree "
        "family is about, solved from the other side. The child is spawned "
        "SUSPENDED and assigned before it runs an instruction, so the assignment is "
        "not a race; the evidence that the job killed it is its own oracle file "
        "stopping short of a RESULT line.")

# ---- resources, and the runtime linked in or shipped beside --------------
S("pe-format-resources", ["w_resource.c", "w_resource.rc"], "format",
  "an executable reading data out of its own PE resource directory",
  cflags=["-lversion"],
  pe=dict(PE64, imports_contains=["version.dll"]),
  expect={"FIND_RESOURCE_RCDATA": "yes", "RCDATA_SIZE": "16",
          "LOAD_RESOURCE": "yes", "LOCK_RESOURCE": "yes",
          "RCDATA_HEX": "0123456789abcdef321076546698badc",
          "RCDATA_HASH": "e8792db24909188d",
          "RCDATA_CONTENT_AS_AUTHORED": "yes",
          "RCDATA_SIZE_IS_SIXTEEN": "yes", "LOAD_STRING_LENGTH": "29",
          "LOAD_STRING": "yes", "STRING_101_LEN": "29",
          "STRING_101_HEX": "6c6578652d776f726b6c6f61642d7265736f757263652d737472696e67",
          "STRING_101_AS_AUTHORED": "yes", "STRING_102_AS_AUTHORED": "yes",
          "ABSENT_STRING_LENGTH": "0", "VERSION_RESOURCE_PRESENT": "yes",
          "GET_FILE_VERSION_INFO_SIZE": "yes", "GET_FILE_VERSION_INFO": "yes",
          "FILE_VERSION_MS": "0x00030001", "FILE_VERSION_LS": "0x00040001",
          "FILE_VERSION": "3.1.4.1", "FILE_VERSION_AS_AUTHORED": "yes",
          "PRODUCT_NAME_LEN": "22",
          "PRODUCT_NAME_HEX": "6c6578652d776f726b6c6f61642d7265736f75726365",
          "PRODUCT_NAME_AS_AUTHORED": "yes"},
  caps=["a PE resource directory built by windres"],
  notes="The only specimen whose sources are not all compiled by a C compiler: "
        "windres turns w_resource.rc into a COFF object carrying a .rsrc section and "
        "the linker puts a PE RESOURCE DIRECTORY in the image. Almost every real "
        "Windows executable has one -- its icon, version block, strings and manifest "
        "all live there -- and nothing else in this corpus produces one. Three "
        "different mechanisms read it back, and GetFileVersionInfoW is the one that "
        "reads the block out of the FILE ON DISK rather than the loaded image, which "
        "is the path installers use. Every declared value comes from the .rc file, "
        "so all of them were known before anything ran.")
S("pe-cxx-static-libstdcxx-shared-libgcc", "x_cxx.cpp", "format",
  "C++ with the standard library linked in but the unwinder still a DLL",
  cflags=["-static-libstdc++"], stage="bundle_cxx_dlls",
  pe={"imports_contains": ["libgcc_s_seh-1.dll"],
      "imports_excludes": ["libstdc++-6.dll"]},
  expect={"STATIC_INIT_ORDER": "12", "EXCEPTION_CAUGHT": "by-base-ref",
          "SORTED": "alpha,beta,gamma", "EXCEPTION_UNWOUND": "yes"},
  caps=["libgcc_s_seh-1.dll beside the exe"],
  notes="The third of the four C++ packaging combinations, and the import table is "
        "read out of the PE to prove which one was actually built rather than which "
        "flags were passed. An exception still has to unwind through a DLL boundary "
        "here, which is not the same code path as the fully static case.")
S("pe-cxx-static-libgcc-shared-libstdcxx", "x_cxx.cpp", "format",
  "the opposite split: the unwinder linked in, the standard library a DLL",
  cflags=["-static-libgcc"], stage="bundle_cxx_dlls",
  pe={"imports_contains": ["libstdc++-6.dll"],
      "imports_excludes": ["libgcc_s_seh-1.dll"]},
  expect={"STATIC_INIT_ORDER": "12", "EXCEPTION_CAUGHT": "by-base-ref",
          "SORTED": "alpha,beta,gamma", "EXCEPTION_UNWOUND": "yes"},
  caps=["libstdc++-6.dll beside the exe"],
  notes="Completes the set with pe-cxx-static-runtime (both in) and "
        "pe-cxx-bundled-runtime-dlls (both out). Four different import tables from "
        "one source file, each verified from the PE headers, which is the packaging "
        "problem real C++ Windows software actually has.")

# ---- GUI, beyond one window and a blocking message loop ------------------
S("pe-gui-console-subsystem-window", "w_gui_console.c", "gui",
  "a CONSOLE-subsystem PE that creates a window and has stdout as well",
  cflags=["-lgdi32"], gui=True, warmup=True, timeout=300.0,
  layers=["wine", "proton-wine"],
  pe=dict(CUI),
  expect={"SUBSYSTEM_DECLARED": "console", "HAS_STDOUT": "yes",
          "REGISTER_CLASS": "yes", "CREATE_WINDOW": "yes",
          "WINDOW_VISIBLE": "yes", "CREATE_CHILD_WINDOW": "yes",
          "CHILD_PARENT_IS_THE_WINDOW": "yes", "CHILD_IS_VISIBLE": "yes",
          "CHILD_CLASS_IS_A_SYSTEM_CLASS": "yes", "SET_WINDOW_TEXT": "yes",
          "WINDOW_TEXT_LENGTH": "13", "WINDOW_TEXT_ROUNDTRIPPED": "yes",
          "MOVE_WINDOW": "yes",
          "CLIENT_AREA_IS_SMALLER_THAN_THE_WINDOW": "yes",
          "WM_PAINT_SEEN": "yes", "WM_SIZE_SEEN": "yes",
          "WM_CLOSE_SEEN": "yes", "WINDOW_REACHED_SCREEN": "yes",
          "CONSOLE_PE_CAN_OWN_A_WINDOW": "yes",
          "MESSAGE_LOOP_COMPLETED": "yes"},
  caps=["a display (runs ONLY on a private X server, never the real desktop)"],
  notes="The PE subsystem is CUI and this program still puts a window on the "
        "screen. Enormous amounts of real Windows software is shaped exactly like "
        "this -- SDL and GLFW programs, debug builds of games, anything built "
        "without -mwindows. A runtime that decides whether a program needs a display "
        "by reading the subsystem byte is wrong about every one of them, and wrong "
        "in the OPPOSITE direction from pe-gui-headless-worker. It also creates a "
        "CHILD window of a system class, which is a different creation path from the "
        "top-level one every other GUI specimen uses.")
S("pe-gui-peek-message-loop", "w_gui_peekloop.c", "gui",
  "a game loop: PeekMessage and a frame counter, not a blocking GetMessage",
  cflags=["-mwindows", "-lgdi32"], gui=True, warmup=True, timeout=300.0,
  layers=["wine", "proton-wine"],
  pe={"subsystem_is_gui": True, "subsystem_is_console": False},
  expect={"REGISTER_CLASS": "yes", "CREATE_WINDOW": "yes",
          "WINDOW_VISIBLE": "yes", "SET_TIMER": "yes",
          "FRAMES_RENDERED": "120", "TARGET_FRAMES": "120",
          "WM_CLOSE_SEEN": "yes", "WM_TIMER_SEEN": "yes",
          "PEEK_MESSAGE_REPORTED_AN_EMPTY_QUEUE": "yes",
          "WINDOW_REACHED_SCREEN": "yes",
          "LOOP_REACHED_ITS_TARGET_AND_STOPPED": "yes",
          "PEEK_MESSAGE_DID_NOT_BLOCK": "yes",
          "TIMER_MESSAGES_ARRIVED_BETWEEN_FRAMES": "yes",
          "PAINTED_AT_LEAST_ONCE": "yes"},
  caps=["a display (runs ONLY on a private X server, never the real desktop)"],
  notes="pe-gui-window uses GetMessageW, which BLOCKS -- that is how a document "
        "application waits for a user. A game does the opposite: it drains the queue "
        "with PeekMessage and renders whether or not anything happened. Those are "
        "completely different paths through a window-system emulation, and a "
        "PeekMessage that blocks turns a 120-frame run into a hang. The loop ends on "
        "a frame count the PROGRAM chose rather than on whenever WM_QUIT happens to "
        "be dequeued, so FRAMES_RENDERED is a deterministic key and not a timing "
        "measurement wearing one's clothes.")
S("pe-gui-gdi-pixels", "w_gui_gdi.c", "gui",
  "GDI rendering checked by reading the pixels back",
  cflags=["-mwindows", "-lgdi32"], gui=True, warmup=True, timeout=300.0,
  layers=["wine", "proton-wine"],
  pe={"subsystem_is_gui": True},
  expect={"GET_DC": "yes", "CREATE_COMPATIBLE_DC": "yes",
          "CREATE_COMPATIBLE_BITMAP": "yes", "CREATE_BRUSHES": "yes",
          "FILL_LEFT": "yes", "FILL_RIGHT": "yes",
          "PIXEL_LEFT": "0x00302010", "PIXEL_RIGHT": "0x008040c0",
          "PIXEL_LEFT_EDGE": "0x00302010", "PIXEL_RIGHT_EDGE": "0x008040c0",
          "EXPECTED_LEFT": "0x00302010", "EXPECTED_RIGHT": "0x008040c0",
          "LEFT_HALF_IS_THE_COLOUR_IT_WAS_PAINTED": "yes",
          "RIGHT_HALF_IS_THE_COLOUR_IT_WAS_PAINTED": "yes",
          "THE_BOUNDARY_IS_EXACTLY_WHERE_IT_WAS_ASKED_FOR": "yes",
          "SET_PIXEL": "yes", "PIXEL_AFTER_SET": "0x00ffffff",
          "SET_PIXEL_TOOK_EFFECT": "yes", "GET_DI_BITS": "yes",
          "DIB_PIXEL_BGR": "302010", "DIB_AGREES_WITH_GETPIXEL": "yes",
          "PIXELS_WERE_REALLY_RENDERED": "yes"},
  caps=["a display (runs ONLY on a private X server, never the real desktop)",
        "GDI rendering into a memory device context"],
  notes="Every other GUI specimen checks that a window existed and that messages "
        "flowed. None of them checks that anything was DRAWN. A COLORREF is "
        "0x00BBGGRR, so RGB(0x10,0x20,0x30) is 0x00302010 and that number is "
        "declared. Two rectangles in different colours, so an implementation that "
        "filled the whole surface with the last brush is caught, and the boundary is "
        "checked on BOTH sides. GetDIBits then reads the same pixel straight out of "
        "the bitmap, bypassing GetPixel entirely, so the two have to agree.")

# ---- the process tree ----------------------------------------------------
#
#   t_launcher.exe -> t_bootstrap.exe -> t_main.exe -> t_helper.exe
#                                                      t_worker.exe
#                                                      t_crash_handler.exe
#
# Built as a deliberate shape rather than as scattered specimens, because in real
# Windows software the launcher exiting immediately is the norm, and that is where
# a supervisor's idea of "the application has finished" is most likely to be wrong.
# Every node writes its own oracle file, so the tree is reconstructible from the
# run directory after every process in it is gone.

# Ten binaries, each with the flags it needs. t_window.exe is the only
# GUI-SUBSYSTEM node -- it is built -mwindows and therefore has no console at all,
# which is exactly the point: in real Windows software the process that owns the
# window and the process doing the work are usually not the same process.
TREE_BUILD = [
    ("t_launcher.c", []),
    ("t_bootstrap.c", []),
    ("t_stage2.c", []),
    ("t_main.c", []),
    ("t_helper.c", []),
    ("t_worker.c", []),
    ("t_grandchild.c", []),
    ("t_crash_handler.c", []),
    ("t_supervisor.c", []),
    ("t_window.c", ["-mwindows", "-lshell32", "-lgdi32"]),
]
TREE_SOURCES = [src for src, _flags in TREE_BUILD]


def tree(fid, mode, prop, **kw):
    # The runner reads t_launcher.oracle, and t_launcher.exe is one binary shared
    # by all eighteen modes -- so its compiled-in identity is the node's name.
    return S(fid, TREE_SOURCES, "process-tree", prop, stage="tree",
             argv=[mode], oracle_file="t_launcher.oracle",
             build_id_expected="t_launcher",
             procbeh=kw.pop("procbeh", "process-tree"), **kw)


tree("pe-tree-chain-wait", "chain-wait",
     "every parent waits for its child, the whole way down",
     settle=1.0, timeout=180.0,
     expect={"MODE": "chain-wait", "WILL_WAIT_FOR_CHILD": "yes",
             "BOOTSTRAP_SPAWN": "ok", "BOOTSTRAP_STARTED": "yes",
             "BOOTSTRAP_WAIT": "signalled", "BOOTSTRAP_EXIT_DECIMAL": "0",
             "LAUNCHER_OUTLIVED_TREE": "yes", "LAUNCHER_EXIT": "0"},
     post={"t_bootstrap.oracle": ["MAIN_WAIT=signalled", "MAIN_EXIT_DECIMAL=0",
                                  "BOOTSTRAP_OUTLIVED_MAIN=yes"],
           "t_main.oracle": ["WORKER_EXIT_DECIMAL=33", "WORKER_EXIT_33=yes"],
           "t_worker.oracle": ["WORKER_EXIT_INTENT=33", "RESULT=PASS"]},
     notes="The easy case, and the reference the other six are compared against: "
           "the launcher's exit really does mean the application has finished.")
tree("pe-tree-launcher-exits", "launcher-exits",
     "the launcher exits immediately and the tree keeps running",
     settle=30.0, timeout=180.0,
     post_complete_when={"t_worker.oracle": "RESULT=PASS"},
     expect={"MODE": "launcher-exits", "WILL_WAIT_FOR_CHILD": "no",
             "BOOTSTRAP_STARTED": "yes", "LAUNCHER_OUTLIVED_TREE": "no",
             "TREE_STILL_RUNNING_AT_LAUNCHER_EXIT": "yes", "LAUNCHER_EXIT": "0"},
     post={"t_bootstrap.oracle": ["MAIN_EXIT_DECIMAL=0"],
           "t_main.oracle": ["WORKER_EXIT_33=yes"],
           "t_worker.oracle": ["RESULT=PASS"]},
     notes="THE case that matters. The launcher exits 0 within milliseconds while "
           "the real application is still starting. Anything that treats the "
           "launcher's exit as the end of the application is wrong here, and the "
           "post-run files are the proof of what happened afterwards.")
tree("pe-tree-bootstrap-only", "bootstrap-only",
     "each parent exits as soon as its child is started",
     settle=30.0, timeout=180.0,
     post_complete_when={"t_worker.oracle": "RESULT=PASS"},
     expect={"MODE": "bootstrap-only", "WILL_WAIT_FOR_CHILD": "no",
             "BOOTSTRAP_STARTED": "yes", "LAUNCHER_OUTLIVED_TREE": "no"},
     post={"t_bootstrap.oracle": ["BOOTSTRAP_OUTLIVED_MAIN=no"],
           "t_main.oracle": ["WORKER_EXIT_33=yes"],
           "t_worker.oracle": ["RESULT=PASS"]},
     notes="The hand-off pattern: nothing above the application is left alive, and "
           "the only process still running is the one nobody is waiting for.")
tree("pe-tree-fanout", "fanout",
     "the application starts three children at once and waits for all of them",
     settle=2.0, timeout=180.0,
     expect={"MODE": "fanout", "BOOTSTRAP_WAIT": "signalled",
             "LAUNCHER_OUTLIVED_TREE": "yes"},
     post={"t_main.oracle": ["CHILDREN_STARTED=3", "ALL_THREE_STARTED=yes",
                             "HELPER_REAPED_CLEAN=yes", "WORKER_REAPED_33=yes",
                             "CRASH_CHILD_REAPED=yes",
                             "PARENT_SURVIVED_CHILD_CRASH=yes"],
           "t_helper.oracle": ["HELPER_COMPLETED=yes", "RESULT=PASS"],
           "t_worker.oracle": ["RESULT=PASS"],
           "t_crash_handler.oracle": ["EXPECT_DEATH=access-violation"]},
     notes="One clean child, one non-zero child and one crashing child, all under "
           "the same parent. The parent must survive all three and report each.")
tree("pe-tree-detach-helper", "detach-helper",
     "a detached helper outlives the application that started it",
     settle=30.0, timeout=180.0,
     post_complete_when={"t_helper.oracle": "RESULT=PASS"},
     expect={"MODE": "detach-helper", "LAUNCHER_OUTLIVED_TREE": "yes"},
     post={"t_main.oracle": ["HELPER_LEFT_RUNNING=yes", "MAIN_EXITS_FIRST=yes",
                             "MAIN_WAITED_FOR_HELPER=no"],
           "t_helper.oracle": ["HELPER_STARTED=yes", "HELPER_COMPLETED=yes",
                               "SURVIVED_SLEEP=yes", "RESULT=PASS"]},
     notes="DETACHED_PROCESS plus CREATE_NEW_PROCESS_GROUP: the helper is cut loose "
           "deliberately. HELPER_COMPLETED=yes in the post-run file is the proof "
           "that work survived the exit of the process that started it.")
tree("pe-tree-orphan-tree", "orphan-tree",
     "every parent exits immediately and a detached helper finishes alone",
     settle=30.0, timeout=180.0,
     post_complete_when={"t_helper.oracle": "RESULT=PASS"},
     expect={"MODE": "orphan-tree", "WILL_WAIT_FOR_CHILD": "no",
             "TREE_STILL_RUNNING_AT_LAUNCHER_EXIT": "yes"},
     post={"t_main.oracle": ["HELPER_LEFT_RUNNING=yes"],
           "t_helper.oracle": ["HELPER_COMPLETED=yes", "RESULT=PASS"]},
     notes="The worst case for supervision: by the time the helper does its work, "
           "every process that could be waited on is gone.")
tree("pe-tree-crash-child", "crash-child",
     "a child terminates abnormally and its parent reports the status",
     settle=2.0, timeout=180.0,
     expect={"MODE": "crash-child", "BOOTSTRAP_WAIT": "signalled",
             "LAUNCHER_OUTLIVED_TREE": "yes", "BOOTSTRAP_EXIT_DECIMAL": "0"},
     post={"t_main.oracle": ["CRASH_WAIT=signalled", "CRASH_EXIT_IS_ABNORMAL=yes",
                             "PARENT_SURVIVED_CHILD_CRASH=yes",
                             "CHILD_STATUS_WAS_NONZERO=yes"],
           "t_crash_handler.oracle": ["WORK_BEFORE_FAULT=done",
                                      "EXPECT_DEATH=access-violation"]},
     notes="The parent exits 0 having observed a child that did not. A supervisor "
           "that looks only at the top of the tree sees a clean run.")

# ---- the tree, made uglier -----------------------------------------------
#
# Six levels rather than three in the deep modes:
#
#   t_launcher -> t_bootstrap -> t_stage2 -> t_main -> t_worker -> t_grandchild
#
# plus t_supervisor (restarts the worker) and t_window (the GUI-subsystem node
# that owns the visible window), each of which can sit at more than one position.

tree("pe-tree-deep-chain", "deep-chain",
     "six levels, every one of the five parents waiting for its child",
     settle=2.0, timeout=240.0,
     expect={"MODE": "deep-chain", "WILL_WAIT_FOR_CHILD": "yes",
             "BOOTSTRAP_STARTED": "yes", "BOOTSTRAP_WAIT": "signalled",
             "BOOTSTRAP_EXIT_DECIMAL": "0", "LAUNCHER_OUTLIVED_TREE": "yes",
             "LAUNCHER_EXIT": "0"},
     post={"t_bootstrap.oracle": ["CHILD_NODE=stage2", "STAGE2_WAIT=signalled",
                                  "STAGE2_EXIT_DECIMAL=0", "BOOTSTRAP_OUTLIVED_MAIN=yes"],
           "t_stage2.oracle": ["LEVEL=2", "MAIN_WAIT=signalled", "MAIN_EXIT_DECIMAL=0",
                               "STAGE2_OUTLIVED_MAIN=yes", "RESULT=PASS"],
           "t_main.oracle": ["LEVEL=3", "WORKER_WAIT=signalled",
                             "WORKER_EXIT_DECIMAL=33", "WORKER_EXIT_33=yes"],
           "t_worker.oracle": ["LEVEL=4", "GRANDCHILD_WAIT=signalled",
                               "GRANDCHILD_EXIT_DECIMAL=44", "GRANDCHILD_EXIT_44=yes",
                               "WORKER_WAITED_FOR_GRANDCHILD=yes", "RESULT=PASS"],
           "t_grandchild.oracle": ["DEPTH=5", "GRANDCHILD_COMPLETED=yes",
                                   "RESULT=PASS"]},
     notes="The deep reference case. A status chosen at the bottom (44) is carried "
           "up through five nested waits, and every level's own file says what it "
           "saw. Three levels is the shape most fixtures stop at; real installers "
           "and launchers stack deeper than that, and each extra level is another "
           "place a supervisor's parent-pid bookkeeping can lose the thread.")
tree("pe-tree-deep-orphan", "deep-orphan",
     "six levels and not one wait anywhere; the deepest node writes the state",
     settle=40.0, timeout=240.0,
     post_complete_when={"t_grandchild.oracle": "RESULT=PASS",
                         "tree_state.dat": "STATE_GRANDCHILD=yes"},
     expect={"MODE": "deep-orphan", "WILL_WAIT_FOR_CHILD": "no",
             "BOOTSTRAP_STARTED": "yes", "LAUNCHER_OUTLIVED_TREE": "no",
             "TREE_STILL_RUNNING_AT_LAUNCHER_EXIT": "yes", "LAUNCHER_EXIT": "0"},
     post={"t_bootstrap.oracle": ["CHILD_NODE=stage2", "BOOTSTRAP_OUTLIVED_MAIN=no"],
           "t_stage2.oracle": ["STAGE2_OUTLIVED_MAIN=no"],
           "t_main.oracle": ["MAIN_WAITED_FOR_WORKER=no", "MAIN_EXITS_FIRST=yes"],
           "t_worker.oracle": ["GRANDCHILD_LEFT_RUNNING=yes",
                               "WORKER_WAITED_FOR_GRANDCHILD=no"],
           "t_grandchild.oracle": ["DEPTH=5", "PARENT_GONE_AFTER_SLEEP=yes",
                                   "GRANDPARENT_GONE_AFTER_SLEEP=yes",
                                   "GRANDCHILD_COMPLETED=yes",
                                   "WROTE_STATE_AFTER_SLEEP=yes", "RESULT=PASS"],
           "tree_state.dat": ["STATE_LAUNCHER=yes", "STATE_BOOTSTRAP=yes",
                              "STATE_STAGE2=yes", "STATE_MAIN=yes",
                              "STATE_WORKER=yes", "STATE_GRANDCHILD=yes"]},
     notes="The worst supervision case in the corpus, and the one that says who owns "
           "persistent state. Six processes, none of which waits for anything, and "
           "the file that has to exist after all of them are gone is written LAST by "
           "the DEEPEST of them -- two and a half seconds after the launcher returned "
           "0. tree_state.dat is checked for the line each node appends, never for "
           "their order, because the order is not a contract. The grandchild proves "
           "it outlived its parent and its grandparent by looking for the flag files "
           "they drop on the way out, rather than inferring it from a sleep.")
tree("pe-tree-grandchild-survives", "grandchild-survives",
     "a grandchild outlives its parent AND its grandparent, under a clean launcher",
     settle=40.0, timeout=240.0,
     post_complete_when={"t_grandchild.oracle": "RESULT=PASS"},
     expect={"MODE": "grandchild-survives", "BOOTSTRAP_WAIT": "signalled",
             "BOOTSTRAP_EXIT_DECIMAL": "0", "LAUNCHER_OUTLIVED_TREE": "yes",
             "LAUNCHER_EXIT": "0"},
     post={"t_main.oracle": ["WORKER_WAIT=signalled", "WORKER_EXIT_DECIMAL=33",
                             "WORKER_EXIT_33=yes"],
           "t_worker.oracle": ["GRANDCHILD_LEFT_RUNNING=yes",
                               "WORKER_WAITED_FOR_GRANDCHILD=no",
                               "GRANDCHILD_WILL_OUTLIVE_ITS_GRANDPARENT=yes"],
           "t_grandchild.oracle": ["PARENT_GONE_AFTER_SLEEP=yes",
                                   "GRANDPARENT_GONE_AFTER_SLEEP=yes",
                                   "GRANDCHILD_COMPLETED=yes", "RESULT=PASS"]},
     notes="The deceptive one. Every process the launcher can see is reaped, and "
           "reaped with the RIGHT status -- the launcher's run looks completely "
           "clean and completely finished -- while a detached grandchild two levels "
           "below keeps working for another two and a half seconds. Anything that "
           "concluded 'the application is done' from the top of this tree is wrong, "
           "and t_grandchild.oracle is what proves it.")
tree("pe-tree-supervisor-restart", "supervisor-restart",
     "a supervisor restarts the same worker three times and collects each status",
     settle=2.0, timeout=240.0,
     expect={"MODE": "supervisor-restart", "BOOTSTRAP_WAIT": "signalled",
             "BOOTSTRAP_EXIT_DECIMAL": "0", "LAUNCHER_OUTLIVED_TREE": "yes"},
     post={"t_main.oracle": ["SUPERVISOR_WAIT=signalled", "SUPERVISOR_EXIT_DECIMAL=0",
                             "SUPERVISOR_EXITED_CLEAN=yes"],
           "t_supervisor.oracle": ["RESTARTS_REQUESTED=3", "GENERATIONS_COMPLETED=3",
                                   "GEN0_EXIT_DECIMAL=33", "GEN1_EXIT_DECIMAL=33",
                                   "GEN2_EXIT_DECIMAL=33",
                                   "EVERY_GENERATION_EXITED_33=yes", "RESULT=PASS"],
           "supervisor.log": ["GEN=0 EXIT=33", "GEN=1 EXIT=33", "GEN=2 EXIT=33",
                              "GENERATIONS=3"],
           "t_worker.oracle": ["WORKER_EXIT_INTENT=33", "RESULT=PASS"]},
     notes="Every crash-restart wrapper has this shape. Three sequential children "
           "from one image in one process, each status collected independently, so a "
           "layer that reported the FIRST child's status for all three would be "
           "caught. It also creates the evidence problem a restart loop always "
           "creates: supervisor.log ACCUMULATES one line per generation while "
           "t_worker.oracle is OVERWRITTEN by each, so after the tree is gone the "
           "only record that three ran is the supervisor's.")
tree("pe-tree-redirect-to-file", "redirect-to-file",
     "the parent redirects BOTH of its child's streams into a file it opened",
     settle=2.0, timeout=240.0,
     expect={"MODE": "redirect-to-file", "BOOTSTRAP_WAIT": "signalled",
             "BOOTSTRAP_EXIT_DECIMAL": "0", "LAUNCHER_OUTLIVED_TREE": "yes"},
     post={"t_main.oracle": ["REDIRECT_TARGET_OPENED=yes", "WORKER_EXIT_DECIMAL=33",
                             "WORKER_STDOUT_LANDED_IN_THE_FILE=yes",
                             "WORKER_STDERR_LANDED_IN_THE_SAME_FILE=yes",
                             "BOTH_STREAMS_WENT_TO_ONE_FILE=yes"],
           "worker_redirected.txt": ["NODE=worker", "WORKER_EXIT_INTENT=33",
                                     "WORKER_STDERR_MARKER=yes"]},
     notes="Handle INHERITANCE done properly: an inheritable file handle, "
           "STARTF_USESTDHANDLES, and bInheritHandles TRUE. The child never knows "
           "its output is a file. worker_redirected.txt is the whole of the child's "
           "two streams, captured off-process by its parent and still on disk after "
           "both of them are gone.")
tree("pe-tree-split-stdio", "split-stdio",
     "a child that inherits one stream and has the other redirected to a file",
     settle=2.0, timeout=240.0,
     expect={"MODE": "split-stdio", "BOOTSTRAP_WAIT": "signalled",
             "BOOTSTRAP_EXIT_DECIMAL": "0", "LAUNCHER_OUTLIVED_TREE": "yes"},
     post={"t_main.oracle": ["SPLIT_TARGET_OPENED=yes",
                             "REDIRECTED_STDOUT_LANDED_IN_THE_FILE=yes",
                             "INHERITED_STDERR_DID_NOT_LAND_IN_THE_FILE=yes",
                             "SPLIT_STDOUT_TO_FILE=yes", "SPLIT_STDERR_INHERITED=yes",
                             "WORKER_EXIT_DECIMAL=33"],
           "worker_split_stdout.txt": ["NODE=worker", "WORKER_EXIT_INTENT=33"]},
     notes="The asymmetric case, and the reason t_worker writes one line to stderr: "
           "the worker's stdout goes to a file its parent opened, while its stderr is "
           "INHERITED all the way up and out of the tree to whoever launched the "
           "launcher. The declaration checks both halves -- the redirected line is in "
           "the file and the inherited line is NOT -- because a layer that merged the "
           "two streams would still pass a test that only looked for the first.")
tree("pe-tree-no-wait-crash", "no-wait-crash",
     "a child crashes and its parent never asks, so nothing above hears about it",
     settle=3.0, timeout=240.0,
     expect={"MODE": "no-wait-crash", "BOOTSTRAP_WAIT": "signalled",
             "BOOTSTRAP_EXIT_DECIMAL": "0", "LAUNCHER_OUTLIVED_TREE": "yes",
             "LAUNCHER_EXIT": "0"},
     post={"t_main.oracle": ["CRASH_CHILD_STARTED=yes",
                             "MAIN_WAITED_FOR_CRASH_CHILD=no",
                             "MAIN_NOTICED_THE_CRASH=no",
                             "MAIN_EXIT_STATUS_IS_CLEAN_ANYWAY=yes", "MAIN_EXIT=0"],
           "t_crash_handler.oracle": ["WORK_BEFORE_FAULT=done",
                                      "EXPECT_DEATH=access-violation"]},
     notes="The mirror image of pe-tree-crash-child, and the more dangerous one. "
           "There the parent waits and reports 0xC0000005; here it never waits, so "
           "every process in the tree exits 0 and the ONLY evidence that anything "
           "died is t_crash_handler.oracle stopping mid-file. A supervisor watching "
           "exit statuses sees a perfect run.")
tree("pe-tree-crash-at-depth", "crash-at-depth",
     "the crash is four levels down and the level above it reports a clean 33",
     settle=3.0, timeout=240.0,
     expect={"MODE": "crash-at-depth", "BOOTSTRAP_WAIT": "signalled",
             "BOOTSTRAP_EXIT_DECIMAL": "0", "LAUNCHER_OUTLIVED_TREE": "yes",
             "LAUNCHER_EXIT": "0"},
     post={"t_main.oracle": ["WORKER_WAIT=signalled", "WORKER_EXIT_DECIMAL=33",
                             "WORKER_EXIT_33=yes"],
           "t_worker.oracle": ["CRASH_CHILD_STARTED=yes",
                               "WORKER_WAITED_FOR_CRASH_CHILD=no",
                               "WORKER_REPORTS_ITS_OWN_CLEAN_STATUS_ANYWAY=yes",
                               "RESULT=PASS"],
           "t_crash_handler.oracle": ["WORK_BEFORE_FAULT=done",
                                      "EXPECT_DEATH=access-violation"]},
     notes="Worse than no-wait-crash because the status above the crash is not just "
           "clean, it is SPECIFIC: the application waits, gets exactly the 33 it was "
           "expecting, and is right to be satisfied. The crash is one level below the "
           "deepest thing anybody is watching.")
tree("pe-tree-gui-leaf", "gui-leaf",
     "the visible window is owned by a detached leaf that outlives its starter",
     settle=60.0, timeout=600.0, gui=True, warmup=True,
     post_complete_when={"t_window.oracle": "RESULT=PASS",
                         "t_main.oracle": "MAIN_EXITS_FIRST="},
     layers=["wine", "proton-wine"],
     expect={"MODE": "gui-leaf", "BOOTSTRAP_WAIT": "signalled",
             "BOOTSTRAP_EXIT_DECIMAL": "0",
             "LAUNCHER_WAITED_ON_A_PROCESS_HANDLE_FOR_THE_WINDOW": "no",
             "WINDOW_DONE_FLAG_SEEN": "yes", "LAUNCHER_EXIT": "0"},
     post={"t_main.oracle": ["DETACHED_WINDOW_STARTED=yes",
                             "MAIN_WAITED_FOR_WINDOW=no",
                             "WINDOW_OWNER_LEFT_RUNNING=yes", "MAIN_EXITS_FIRST=yes"],
           "t_window.oracle": ["NODE=window", "SUBSYSTEM_DECLARED=windows",
                               "CREATE_WINDOW=yes", "WINDOW_VISIBLE=yes",
                               "WINDOW_REACHED_SCREEN=yes",
                               "STARTER_GONE_BEFORE_WINDOW_CAME_DOWN=yes",
                               "SAW_TREE_DONE_FLAG=no", "WM_CLOSE_SEEN=yes",
                               "WINDOW_HELD_AND_CLOSED=yes", "RESULT=PASS"]},
     caps=["a display (runs ONLY on a private X server, never the real desktop)"],
     notes="Window ownership at the BOTTOM of the tree. t_window.exe is the only "
           "GUI-subsystem binary in the family, it is started DETACHED, and the "
           "process that started it exits milliseconds later -- so for the two and a "
           "half seconds the window is up there is no live ancestor between it and "
           "the launcher. A window belongs to the thread that created it and cannot "
           "outlive that thread, so 'the window outlives the process that created "
           "it' is not a thing any program can do; what this shows is the real "
           "version of that -- the window, and the process owning it, outliving "
           "everything that STARTED them, which it proves by finding main's exit "
           "flag on disk. The launcher then holds the private display open until "
           "the window node's own flag appears; see the comment in t_launcher.c for "
           "why that wait is about the X server and not about the shape.")
tree("pe-tree-gui-top", "gui-top",
     "the launcher owns the window and work two levels down takes it away",
     settle=2.0, timeout=600.0, gui=True, warmup=True,
     layers=["wine", "proton-wine"],
     expect={"MODE": "gui-top", "WINDOW_CHILD_SPAWN": "ok",
             "WINDOW_CHILD_STARTED": "yes",
             "LAUNCHER_OWNED_THE_WINDOW_CHILD": "yes",
             "BOOTSTRAP_WAIT": "signalled", "BOOTSTRAP_EXIT_DECIMAL": "0",
             "WINDOW_CHILD_WAIT": "signalled",
             "LAUNCHER_OUTLIVED_ITS_WINDOW": "yes",
             "LAUNCHER_OUTLIVED_TREE": "yes", "LAUNCHER_EXIT": "0"},
     post={"t_window.oracle": ["NODE=window", "CREATE_WINDOW=yes",
                               "WINDOW_VISIBLE=yes", "SAW_TREE_DONE_FLAG=yes",
                               "WINDOW_HELD_AND_CLOSED=yes", "RESULT=PASS"],
           "t_main.oracle": ["WORKER_EXIT_33=yes",
                             "WINDOW_IS_NOT_OWNED_BY_THIS_NODE=yes"]},
     caps=["a display (runs ONLY on a private X server, never the real desktop)"],
     notes="The splash screen, and the opposite end of the tree from gui-leaf. The "
           "window belongs to a direct child of the LAUNCHER, off to one side of the "
           "payload chain entirely, and it comes down because of a SIDE EFFECT of "
           "work two levels below it -- the worker drops tree_done.flag on its way "
           "out and the window node, which has no handle on the worker and no idea "
           "it exists, notices the file and closes. That is how real launchers and "
           "their payloads are coupled, and SAW_TREE_DONE_FLAG=yes is the evidence "
           "it happened that way rather than on a timeout.")
tree("pe-tree-wait-timeout", "wait-timeout",
     "a parent waits with a timeout, gives up, and exits while the child works on",
     settle=40.0, timeout=240.0,
     post_complete_when={"t_helper.oracle": "RESULT=PASS"},
     expect={"MODE": "wait-timeout", "BOOTSTRAP_WAIT": "signalled",
             "BOOTSTRAP_EXIT_DECIMAL": "0", "LAUNCHER_OUTLIVED_TREE": "yes",
             "LAUNCHER_EXIT": "0"},
     post={"t_main.oracle": ["SLOW_HELPER_STARTED=yes", "HELPER_WAIT=timeout",
                             "MAIN_GAVE_UP_WAITING=yes", "MAIN_WAIT_TIMEOUT_MS=500",
                             "HELPER_LEFT_RUNNING=yes", "MAIN_EXITS_FIRST=yes"],
           "t_helper.oracle": ["SLEEP_MS=4000", "HELPER_COMPLETED=yes",
                               "SURVIVED_SLEEP=yes", "RESULT=PASS"]},
     notes="The third kind of parent, after 'waits' and 'never waits': one that "
           "waits with a DEADLINE. The 500 ms timeout against a 4000 ms child is "
           "wide enough that WAIT_TIMEOUT is the only possible answer, and giving up "
           "does not kill the child -- so the launcher above reports a clean, fully "
           "waited-for run at a moment when the real work has three and a half "
           "seconds left. HELPER_COMPLETED=yes, written afterwards, is the proof.")

# --------------------------------------------------------------------------
# Compiler differentials: a chosen subset, each with the assumption it probes.
# --------------------------------------------------------------------------

DIFFERENTIALS = [
    ("pe-run-cpu-bound", ["mingw64-O0", "clang-mingw64-O2", "mingw32-O2"],
     "The checksum is 64-bit integer arithmetic and must be bit-identical under "
     "every toolchain AND in a 32-bit process. A difference means a miscompile, "
     "undefined behaviour, or a 64-bit type that is not what it claims."),
    ("pe-proc-threads-4", ["clang-mingw64-O2"],
     "clang emits different thread-local and atomic sequences than gcc for the "
     "same CreateThread and CRITICAL_SECTION code."),
    ("pe-outcome-abnormal-av", ["clang-mingw64-O2"],
     "A null dereference is undefined behaviour and an optimiser may delete it. "
     "A specimen that stops crashing is a broken fixture, not a passing one."),
    ("pe-ipc-named-pipe", ["mingw32-O2"],
     "A 32-bit process using named pipes runs through WoW64, which is a different "
     "path through the layer entirely."),
    ("pe-fs-unicode-path", ["mingw32-O2"],
     "Unicode filenames from a 32-bit process: the wide-character path and the "
     "WoW64 path at the same time."),
    ("pe-format-console-x64", ["mingw64-O0", "clang-mingw64-O2"],
     "The control case under every toolchain that can build it."),
    ("pe-sync-interlocked", ["clang-mingw64-O2", "mingw32-O2"],
     "clang lowers the Interlocked* intrinsics through its own atomic builtins "
     "rather than gcc's, and a 32-bit process uses different instructions again. "
     "The totals are exact, so a lowering that is not really atomic shows up as a "
     "number that is LOW rather than as a crash -- the one failure mode a "
     "correctness test can see and a smoke test cannot."),
    ("pe-tls-both-mechanisms", ["clang-mingw64-O2", "mingw32-O2"],
     "__thread on mingw needs a TLS DIRECTORY in the PE image, which the two "
     "compilers emit differently and which PE32 lays out differently from PE32+. "
     "The specimen checks the API slots and the compiler's own TLS side by side, so "
     "a toolchain that got one of them wrong is distinguishable from a layer that "
     "got both wrong."),
    ("pe-proc-fibers", ["mingw32-O2"],
     "A fiber switch is a context switch the implementation performs itself, and "
     "on i686 that is entirely different code: different register set, different "
     "stack layout, and no SEH unwinding table of the x86-64 kind. The switching "
     "sequence must still come out mAmBmAm."),
    ("pe-exception-unhandled-filter", ["clang-mingw64-O2"],
     "The top-level filter is reached through the PE's .pdata/.xdata unwinding "
     "tables, and clang generates those with its own backend. A filter that never "
     "ran would turn a declared exit 9 into a raw access violation, which is "
     "precisely the difference a crash reporter exists to make."),
    ("pe-fs-memory-mapped-file", ["mingw32-O2"],
     "A 32-bit process maps views in a 4 GiB address space with different "
     "alignment and a different base, and MapViewOfFile is where that stops being "
     "invisible. The hash of the mapped bytes must be identical anyway."),
    ("pe-format-resources", ["clang-mingw64-O2"],
     "The resource object comes from GNU windres either way; the assumption under "
     "test is that clang's linker still produces a .rsrc directory FindResourceW "
     "can walk, and that the version block is still findable in the file on disk."),
    ("pe-outcome-exit-looks-like-a-crash", ["mingw32-O2"],
     "A 32-bit process exiting with a status that looks like an access violation "
     "must still be distinguishable from one that suffered it, and WoW64 is an "
     "extra layer between the guest's ExitProcess and the status the caller sees."),
    ("pe-io-binary-nul", ["mingw64-O0"],
     "The payload is all 256 byte values written by a loop. At -O2 that loop may be "
     "vectorised or turned into a table; at -O0 it is not. The bytes that come out "
     "must be identical, which is what makes the declared hash a property of the "
     "program rather than of the optimiser."),
    ("pe-cxx-static-runtime", ["clang-mingw64-O2"],
     "clang++ pairs its own unwinder with this libstdc++. An exception that failed "
     "to unwind across that pairing would change EXCEPTION_CAUGHT from "
     "by-base-ref to wrong, or abort the process outright."),
    ("pe-sync-condition-variable", ["clang-mingw64-O2"],
     "SRWLOCK and CONDITION_VARIABLE are manipulated in the process's own memory, "
     "so the surrounding loads and stores -- and the memory ordering the compiler "
     "chooses for them -- are part of the mechanism rather than beside it."),
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
            # A differential is its OWN binary, compiled with its own id, so the
            # compiled-in identity it must report is the clone's -- not the
            # base's, which the deep copy above brought along. The exception is a
            # process-tree base, whose binaries are shared and therefore identify
            # themselves by node name; that value is already correct and copying
            # it is what we want.
            if base["declared"].get("build_id_expected") == base_id:
                clone["declared"]["build_id_expected"] = clone["id"]
            pe = clone["declared"]["pe"]
            if TOOLCHAINS[tc]["target"] != "x86_64":
                # A 32-bit build cannot satisfy a 64-bit declaration, and the
                # pointer size it reports is its own, not the base's.
                pe.pop("pe_format", None)
                pe.pop("machine_is_x86_64", None)
                clone["declared"]["expect"].pop("POINTER_BITS", None)
                clone["declared"]["expect"].pop("LIB_POINTER_BITS", None)
            if tc.endswith("-O0"):
                pe.pop("stripped", None)
                pe.pop("has_symbol_table", None)
            SPECIMENS.append(clone)


expand_differentials()

# proton-run is baselined for a REPRESENTATIVE SAMPLE only -- see the layer record
# in the index for the four measured reasons. Every other specimen keeps its
# native/wine/proton-wine cells.
PROTON_RUN_SAMPLE = {
    "pe-format-console-x64",          # the control case
    "pe-format-console-x86",          # 32-bit through WoW64
    "pe-io-both-streams",             # whether either stream survives the launcher
    "pe-io-stdin-under-proton-run",   # the stdin probe, which exists for this layer
    "pe-interface-module-path",       # the path mapping the launcher hands over
    "pe-outcome-exit-42",             # exit-status fidelity
    "pe-outcome-abnormal-av",         # abnormal-status fidelity
    "pe-fs-unicode-path",             # a non-ASCII filename
    "pe-registry-roundtrip",          # the registry in Proton's own prefix
    "pe-dll-explicit-wrong-arch",     # a distinct loader error
    "pe-proc-threads-4",              # threads
    "pe-socket-tcp-loopback",         # networking
    "pe-tree-launcher-exits",         # the launcher-exits-immediately tree
    "pe-layer-identity",              # what this layer says it is
}
for _s in SPECIMENS:
    if "proton-run" in _s["layers"] and _s["id"] not in PROTON_RUN_SAMPLE:
        _s["layers"] = [l for l in _s["layers"] if l != "proton-run"]

# Cross-key rules a single expect= value cannot express.
_by_id = {s["id"]: s for s in SPECIMENS}
_by_id["pe-fs-persistent-state"]["declared"]["expect_sequence"] = {"RUN_COUNT": ["1", "2"]}

# A MEASURED, DETERMINISTIC per-layer difference found by the differential it was
# added for, and the most substantive result in this generation.
#
# pe-tls-both-mechanisms passes everywhere when gcc builds it, under both Wines, at
# both -O2 and 32-bit. Rebuilt by CLANG for the same target it still passes under
# the SYSTEM Wine -- complete oracle, RESULT=PASS, exit 0 -- and under PROTON's Wine
# it dies with an access violation, exit 5, immediately after TlsAlloc returns: the
# oracle file stops at OBS_TLS_SLOT_INDEX, before the first touch of the __thread
# variable and before CreateEventW. Deterministic across repeats on both layers.
#
# That is a legitimate program, built by a legitimate toolchain that is installed
# on this host, crashing under one Wine and not another -- which is precisely the
# assumption the differential named ("clang and gcc build the PE TLS directory
# differently"). It is DECLARED here rather than left as a mystery failure, in the
# same way pe-outcome-abnormal-raise declares its Wine-versus-Proton split: the
# wine cell keeps every expectation the base specimen has, and the proton-wine cell
# declares the exit status and exactly how far the program gets.
_tls_clang = _by_id.get("pe-tls-both-mechanisms--clang-mingw64-O2")
if _tls_clang:
    _d = _tls_clang["declared"]
    _full = dict(_d["expect"])
    _d["expect"] = {"TLS_ALLOC": "yes"}          # as far as it gets on every layer
    _d["expect_by_layer"] = {"wine": dict(_full, RESULT="PASS")}
    _d["requires_result_pass"] = False           # checked per layer above instead
    _d["exit_code"] = 0
    _d["exit_code_by_layer"] = {"proton-wine": 5}
    _d["measured_layer_difference"] = (
        "clang-built __thread/TLS faults under Proton's Wine (exit 5, access "
        "violation, oracle stops at OBS_TLS_SLOT_INDEX) and works under the system "
        "Wine (exit 0, RESULT=PASS). The gcc build of the SAME source passes on "
        "both, so the crash belongs to the combination of clang's TLS lowering and "
        "Proton's Wine, not to either alone and not to the specimen.")
    _tls_clang["property"] += " [MEASURED LAYER DIFFERENCE]"
for _sid in list(_by_id):
    if _sid.startswith("pe-fs-unicode-path"):
        _by_id[_sid]["declared"]["equal_keys"] = [["TARGET_NAME_HEX", "FOUND_NAME_HEX"]]


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

def find_runtime_dll(name):
    """Locate a MinGW runtime DLL to bundle. Returns None if it is not on this
    host, which makes the specimen that needs it a BUILD FAILURE and therefore
    not coverage -- never a silently skipped row."""
    roots = ["/usr/lib/gcc/x86_64-w64-mingw32", "/usr/x86_64-w64-mingw32/lib",
             "/usr/lib/x86_64-linux-gnu", "/usr/share/mingw-w64"]
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            if name in files:
                return os.path.join(dirpath, name)
    return None


CXX_RUNTIME_DLLS = ["libstdc++-6.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll"]


def windres_for(toolchain):
    """A .rc is not compiled by a C compiler: windres turns it into a COFF object
    carrying a .rsrc section, and the linker puts a PE resource DIRECTORY in the
    image. It must match the target architecture."""
    return ("i686-w64-mingw32-windres" if TOOLCHAINS[toolchain]["target"] != "x86_64"
            else "x86_64-w64-mingw32-windres")


def build_resources(spec, out):
    """Compile every .rc source of a specimen. Returns (objects, records). A
    failure here is a BUILD failure like any other: a resource specimen whose
    resources silently did not get in would be a hole disguised as a row."""
    objs, records = [], []
    for s in spec["sources"]:
        if not s.endswith(".rc"):
            continue
        obj = os.path.join(out, "res", "%s--%s.o" % (spec["id"], s[:-3]))
        os.makedirs(os.path.dirname(obj), exist_ok=True)
        cmd = [windres_for(spec["toolchain"]), "-I", SPECS,
               os.path.join(SPECS, s), "-O", "coff", "-o", obj]
        r = sh(cmd)
        records.append({"source": s, "command": " ".join(cmd),
                        "ok": r.returncode == 0 and os.path.exists(obj),
                        "stderr": r.stderr.strip()[:1000]})
        objs.append(obj)
    return objs, records


def compile_cmd(spec, out, target, res_objs=()):
    tc = TOOLCHAINS[spec["toolchain"]]
    cxx = spec["language"] == "c++"
    driver = tc["cxx"] if cxx else tc["cc"]
    flags = (COMMON_CXX if cxx else COMMON_C) + tc["opt"] + tc["extra"]
    # The specimen's identity, COMPILED IN. FIXTURE_ID arrives through the
    # environment, which a conforming runtime must reset (FORMAT-0.1 §9.5.2), and
    # here that value also NAMES the oracle file -- so with the environment
    # cleared, every specimen built from one source would write to one file and
    # overwrite the others, silently. See oracle_win.h.
    flags = flags + ['-DLEXE_FIXTURE_BUILD_ID="%s"' % spec["id"]]
    srcs = [os.path.join(SPECS, s) for s in spec["sources"] if not s.endswith(".rc")]
    cmd = ([driver] + flags + srcs + list(res_objs) + ["-o", target]
           + spec["cflags"] + LINK_REPRODUCIBLE)
    if spec["stage"] in ("bundle_wlib", "isolate_exe") and "w_dll_implicit.c" in spec["sources"]:
        cmd += ["-L" + os.path.join(out, "dll"), "-lwlib"]
    return cmd


def build_support(out):
    """The DLLs, the six tree binaries, and the located C++ runtime DLLs."""
    record = {"dlls": [], "tree": [], "cxx_runtime_dlls": {}}
    dlldir = os.path.join(out, "dll")
    os.makedirs(dlldir, exist_ok=True)
    for lib in DLLS:
        tc = TOOLCHAINS[lib["toolchain"]]
        libdir = os.path.join(dlldir, lib["dir"]) if lib.get("dir") else dlldir
        os.makedirs(libdir, exist_ok=True)
        target = os.path.join(libdir, lib["name"])
        cmd = ([tc["cc"]] + COMMON_C + tc["opt"] + lib.get("cflags", [])
               + ["-shared", os.path.join(SPECS, lib["src"]), "-o", target]
               + LINK_REPRODUCIBLE)
        if lib["implib"]:
            cmd += ["-Wl,--out-implib," + os.path.join(dlldir, lib["implib"])]
        r = sh(cmd)
        record["dlls"].append({"name": lib["name"], "toolchain": lib["toolchain"],
                               "dir": lib.get("dir", ""),
                               "command": " ".join(cmd), "ok": r.returncode == 0,
                               "stderr": r.stderr.strip()[:1000],
                               "sha256": sha256_file(target) if os.path.exists(target) else None})
    treedir = os.path.join(out, "tree")
    os.makedirs(treedir, exist_ok=True)
    tc = TOOLCHAINS["mingw64-O2"]
    for src, extra in TREE_BUILD:
        target = os.path.join(treedir, src[:-2] + ".exe")
        # The tree binaries are built ONCE and shared by every tree mode, so the
        # most they can honestly carry as a compiled-in identity is their own
        # NODE name -- t_launcher, t_window and so on. Which tree FIXTURE a run
        # belongs to comes from the mode argument and the run directory, not from
        # the binary, and pretending otherwise would be a compiled-in claim that
        # is false for seventeen of the eighteen modes.
        node = src[:-2]
        cmd = ([tc["cc"]] + COMMON_C + tc["opt"]
               + ['-DLEXE_FIXTURE_BUILD_ID="%s"' % node]
               + [os.path.join(SPECS, src), "-o", target] + list(extra)
               + LINK_REPRODUCIBLE)
        r = sh(cmd)
        record["tree"].append({"name": os.path.basename(target),
                               "command": " ".join(cmd), "ok": r.returncode == 0,
                               "extra_flags": list(extra),
                               "stderr": r.stderr.strip()[:1000],
                               "sha256": sha256_file(target) if os.path.exists(target) else None})
    for name in CXX_RUNTIME_DLLS:
        found = find_runtime_dll(name)
        record["cxx_runtime_dlls"][name] = found
    return record


def build_one(spec, out):
    if spec["stage"] == "tree":
        target = os.path.join(out, "tree", "t_launcher.exe")
        return {"toolchain": spec["toolchain"], "compiler": TOOLCHAINS[spec["toolchain"]]["cc"],
                "compiler_version": TOOL_VERSIONS.get(TOOLCHAINS[spec["toolchain"]]["cc"]),
                "flags": COMMON_C + TOOLCHAINS[spec["toolchain"]]["opt"],
                "command": "(shared process-tree build: see support_binaries.tree)",
                "ok": os.path.exists(target), "seconds": 0.0, "warnings": "",
                "target": target, "shared_build": True}
    target = os.path.join(out, "bin", spec["id"] + ".exe")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    t0 = time.time()
    res_objs, res_records = build_resources(spec, out)
    res_ok = all(x["ok"] for x in res_records)
    cmd = compile_cmd(spec, out, target, res_objs)
    r = sh(cmd)
    return {"toolchain": spec["toolchain"], "compiler": cmd[0],
            "compiler_version": TOOL_VERSIONS.get(cmd[0], "?"),
            "flags": cmd[1:], "command": " ".join(cmd),
            "resources": res_records,
            "ok": res_ok and r.returncode == 0 and os.path.exists(target),
            "seconds": round(time.time() - t0, 2),
            "warnings": ((r.stderr.strip()
                          + ("" if res_ok else "\n[windres] "
                             + "; ".join(x["stderr"] for x in res_records)))[:4000]),
            "target": target,
            "shared_build": False}


def build_native_twin(spec, out):
    """The same source built as a Linux ELF, for the reference cell. Only the
    portable specimens can have one; anything that includes windows.h cannot, and
    says so rather than pretending."""
    target = os.path.join(out, "native", spec["id"])
    os.makedirs(os.path.dirname(target), exist_ok=True)
    # The same compiled-in identity the Windows build gets. Missing it here is
    # what broke the entire native layer once: oracle_win.h named the oracle file
    # from it, every twin wrote "(not-compiled-in).oracle", and the runner found
    # no oracle file for any native specimen.
    cmd = (["gcc"] + COMMON_C + ["-O2"]
           + ['-DLEXE_FIXTURE_BUILD_ID="%s"' % spec["id"]]
           + [os.path.join(SPECS, s) for s in spec["sources"]]
           + ["-o", target])
    r = sh(cmd)
    return {"command": " ".join(cmd), "ok": r.returncode == 0 and os.path.exists(target),
            "warnings": r.stderr.strip()[:2000], "target": target,
            "sha256": sha256_file(target) if os.path.exists(target) else None}


# --------------------------------------------------------------------------
# Layers
# --------------------------------------------------------------------------

BASE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "HOME": os.path.expanduser("~")}

# Registry setting that stops Wine launching a debugger on an unhandled fault.
# Without it a crashing specimen hangs for the whole timeout instead of dying,
# and its parent's wait times out too: found by running the tree, not by reading
# documentation.
WINEDBG_KEY = "HKCU" + BS + "Software" + BS + "Wine" + BS + "WineDbg"

# proton-run is SERIALISED. Measured: two concurrent `proton run` invocations
# sharing one Proton prefix intermittently produce a run in which the guest never
# starts at all -- no oracle file, no output, exit 0. Five serial repeats are
# stable; parallel repeats are not. Every other layer runs in parallel.
PROTON_LOCK = threading.Semaphore(1)

# GUI launches are SERIALISED and get a PREFIX OF THEIR OWN, for a measured
# reason. A GUI specimen runs on a fresh private X display every launch, but a
# Wine PREFIX has one set of per-prefix service processes (wineserver,
# explorer.exe, winedevice.exe) shared by everything using it -- and those
# services keep X11 state. Running several GUI specimens in parallel against one
# prefix therefore asks one set of services to serve several private displays at
# once, and the result, observed across five repeats, was an occasional
#
#   X Error of failed request: BadWindow, Major opcode 10 (X_UnmapWindow)
#
# which Xlib's default handler turns into an immediate exit -- killing the guest
# mid-run and leaving a truncated oracle. It hit a different GUI specimen each
# generation, which is exactly the shape of a defect that gets blamed on whatever
# it happened to land on.
#
# So: GUI work runs in prefix-wine-gui / prefix-protonwine-gui, one launch at a
# time, and the wineserver for that prefix is killed before each launch so the
# services restart on the display actually in use. Non-GUI specimens keep their
# own prefixes and keep running in parallel.
GUI_LOCK = threading.Semaphore(1)


def wine_prefix(layer, out, gui):
    if layer == "wine":
        return os.path.join(out, "prefix-wine-gui" if gui else "prefix-wine")
    if layer == "proton-wine":
        return os.path.join(out, "prefix-protonwine-gui" if gui else "prefix-protonwine")
    return None


def wineserver_for(layer):
    if layer == "proton-wine":
        return os.path.join(PROTON_DIR, "files", "bin", "wineserver")
    return "wineserver"


def layer_env(layer, out, spec, rundir):
    env = dict(BASE_ENV)
    env["FIXTURE_ID"] = spec["id"]
    env["WINEDEBUG"] = "-all"
    env["WINEDLLOVERRIDES"] = "mscoree,mshtml="
    if layer in ("wine", "proton-wine"):
        env["WINEPREFIX"] = wine_prefix(layer, out, spec["gui"])
    elif layer == "proton-run":
        env["STEAM_COMPAT_DATA_PATH"] = os.path.join(out, "prefix-protonrun")
        env["DISPLAY"] = PROTON_DISPLAY[0] or ":96"
        env["STEAM_COMPAT_CLIENT_INSTALL_PATH"] = STEAM_CLIENT
        env["PROTON_LOG"] = "0"
    if layer == "native":
        env["TMPDIR"] = os.path.join(rundir, "tmp")
        os.makedirs(env["TMPDIR"], exist_ok=True)
    env.update(spec["env"])
    return env


def layer_command(layer, exe, argv):
    if layer == "native":
        return [exe] + argv
    if layer == "wine":
        return ["wine", exe] + argv
    if layer == "proton-wine":
        return [PROTON_WINE, exe] + argv
    if layer == "proton-run":
        return ["python3", PROTON_SCRIPT, "run", exe] + argv
    raise ValueError(layer)


def write_display_helper(out):
    path = os.path.join(out, "run_on_private_display.sh")
    with open(path, "w", newline="\n") as f:
        f.write("#!/bin/bash\n"
                "# Run a command on a PRIVATE X server. No automated test may put a\n"
                "# window on the developer's desktop; this is the project's own\n"
                "# namespaced-Xvfb helper, used unchanged.\n"
                "set -u\n"
                'source "%s"\n'
                "if ! pd_available; then\n"
                '  echo "PD_UNAVAILABLE=$PD_UNAVAILABLE_REASON" >&2\n'
                "  exit 90\n"
                "fi\n"
                'num="$1"; shift\n'
                'pd_run "$num" -- "$@"\n' % PD_LIB)
    os.chmod(path, 0o755)
    return path


def setup_layers(out, layers, probe_exe):
    """Create and configure each layer's prefix once, and record exactly what was
    done to it: prefix configuration is part of the definition of the layer, so it
    belongs in the index."""
    records = {}
    if "native" in layers:
        records["native"] = {"kind": "direct ELF execution",
                             "reference": True,
                             "notes": "The same source built for Linux by gcc -O2."}
    if "wine" in layers:
        env = dict(BASE_ENV)
        env["WINEPREFIX"] = os.path.join(out, "prefix-wine")
        env["WINEDEBUG"] = "-all"
        t0 = time.time()
        boot = sh(["wineboot", "-u"], env=env)
        reg = sh(["wine", "reg", "add", WINEDBG_KEY, "/v", "ShowCrashDialog",
                  "/t", "REG_DWORD", "/d", "0", "/f"], env=env)
        # NOT `wineserver -p`. A persistent server was tried here to stop the
        # "wine client error:0: recvmsg: Connection reset by peer" flake (see
        # HARNESS_FAULT_MARKERS) and it made things worse in two ways: it inherits
        # the pipes of whatever started it, so every later capture_output call
        # against that prefix waits for an EOF that never comes; and it survives an
        # interrupted generation, so it poisons the prefix for the next one --
        # exactly the trap `proton run` already sets. The flake is handled by
        # detecting and RECORDING a harness fault instead.
        persist = 0
        gui_env = dict(env)
        gui_env["WINEPREFIX"] = os.path.join(out, "prefix-wine-gui")
        gui_boot = sh(["wineboot", "-u"], env=gui_env)
        sh(["wine", "reg", "add", WINEDBG_KEY, "/v", "ShowCrashDialog",
            "/t", "REG_DWORD", "/d", "0", "/f"], env=gui_env)
        records["wine"] = {
            "kind": "system wine, directly",
            "binary": "wine", "version": TOOL_VERSIONS.get("wine"),
            "prefix": env["WINEPREFIX"],
            "gui_prefix": gui_env["WINEPREFIX"],
            "gui_prefix_ok": gui_boot.returncode == 0,
            "prefix_creation_seconds": round(time.time() - t0, 1),
            "wineboot_ok": boot.returncode == 0,
            "configuration": [WINEDBG_KEY + " ShowCrashDialog = 0 (no debugger on "
                              "an unhandled fault, so a crash dies instead of hanging)",
                              "NOT wineserver -p: a persistent server inherits the "
                              "pipes of whatever started it and survives an "
                              "interrupted generation, so the connection-reset "
                              "flake is detected and recorded instead",
                              "a SEPARATE prefix for GUI specimens, whose launches "
                              "are serialised and whose wineserver is killed before "
                              "each launch: per-prefix Wine services keep X11 state "
                              "and cannot serve several private displays at once"],
            "configuration_ok": reg.returncode == 0 and persist == 0,
            "stdio_observable": True,
        }
    if "proton-wine" in layers:
        pfxenv = dict(BASE_ENV)
        pfxenv["WINEPREFIX"] = os.path.join(out, "prefix-protonwine")
        pfxenv["WINEDEBUG"] = "-all"
        os.makedirs(pfxenv["WINEPREFIX"], exist_ok=True)
        t0 = time.time()
        boot = sh([PROTON_WINE, "wineboot", "-u"], env=pfxenv, timeout=900)
        reg = sh([PROTON_WINE, "reg", "add", WINEDBG_KEY, "/v", "ShowCrashDialog",
                  "/t", "REG_DWORD", "/d", "0", "/f"], env=pfxenv, timeout=300)
        persist = 0            # see the note on the wine layer: no persistent server
        gpfx = dict(pfxenv)
        gpfx["WINEPREFIX"] = os.path.join(out, "prefix-protonwine-gui")
        os.makedirs(gpfx["WINEPREFIX"], exist_ok=True)
        gui_boot = sh([PROTON_WINE, "wineboot", "-u"], env=gpfx, timeout=900)
        sh([PROTON_WINE, "reg", "add", WINEDBG_KEY, "/v", "ShowCrashDialog",
            "/t", "REG_DWORD", "/d", "0", "/f"], env=gpfx, timeout=300)
        records["proton-wine"] = {
            "kind": "the wine binary inside Proton, run directly, headless",
            "binary": PROTON_WINE,
            "proton_build": HOST["proton_version"],
            "prefix": pfxenv["WINEPREFIX"],
            "gui_prefix": gpfx["WINEPREFIX"],
            "gui_prefix_ok": gui_boot.returncode == 0,
            "prefix_creation_seconds": round(time.time() - t0, 1),
            "wineboot_ok": boot.returncode == 0,
            "configuration": [WINEDBG_KEY + " ShowCrashDialog = 0",
                              "no persistent server (see the wine layer's note)",
                              "a SEPARATE, serialised prefix for GUI specimens"],
            "configuration_ok": reg.returncode == 0 and persist == 0,
            "stdio_observable": True,
            "notes": "Proton's Wine with a prefix of its own, and WITHOUT the proton "
                     "script. It separates 'Proton's Wine behaves differently' from "
                     "'Proton's launcher behaves differently', and it is the cell "
                     "that carries Proton coverage in this corpus, because the "
                     "launcher itself could not be baselined here -- see proton-run.",
        }
    if "proton-run" in layers:
        env = dict(BASE_ENV)
        env["STEAM_COMPAT_DATA_PATH"] = os.path.join(out, "prefix-protonrun")
        env["STEAM_COMPAT_CLIENT_INSTALL_PATH"] = STEAM_CLIENT
        env["PROTON_LOG"] = "0"
        env["WINEDEBUG"] = "-all"
        os.makedirs(os.path.join(env["STEAM_COMPAT_DATA_PATH"], "pfx"), exist_ok=True)
        display = start_corpus_display()
        env["DISPLAY"] = PROTON_DISPLAY[0]
        t0 = time.time()
        pfxenv = dict(BASE_ENV)
        pfxenv["WINEPREFIX"] = os.path.join(env["STEAM_COMPAT_DATA_PATH"], "pfx")
        pfxenv["WINEDEBUG"] = "-all"
        pre = sh([PROTON_WINE, "wineboot", "-u"], env=pfxenv, timeout=900)
        first = sh(["python3", PROTON_SCRIPT, "run", probe_exe], env=env,
                   cwd=env["STEAM_COMPAT_DATA_PATH"], timeout=300)
        records["proton-run"] = {
            "kind": "Proton's own entry point: python3 proton run",
            "proton_build": HOST["proton_version"],
            "prefix": env["STEAM_COMPAT_DATA_PATH"],
            "prefix_creation_seconds": round(time.time() - t0, 1),
            "headless_wineboot_ok": pre.returncode == 0,
            "first_run_ok": first.returncode == 0,
            "first_run_exit": first.returncode,
            "corpus_display": display,
            "configuration": [WINEDBG_KEY + " ShowCrashDialog = 0 (in the shared pfx)"],
            "stdio_observable": False,
            "sample_only": True,
            "requires_working_display": True,
            "must_be_serialised": True,
            "must_not_run_in_a_mount_namespace": True,
            "findings": [
                "The guest program's stdout and stderr do NOT reach the caller "
                "through this entry point, while its exit code and its file side "
                "effects do. This is why every specimen writes its oracle to a file.",
                "It does not return at all unless DISPLAY names a WORKING X server. "
                "Not merely set, and not a display that does not exist. The guest "
                "runs to completion and writes its files either way; Proton's "
                "launcher is what never exits. wine and proton-wine both run "
                "headless, so this belongs to the launcher, not to Proton's Wine.",
                "A guest that reads stdin blocks forever: the program starts, "
                "writes its first oracle line, and never sees data or EOF, even "
                "with stdin at /dev/null.",
                "Two concurrent invocations against one prefix intermittently "
                "produce a run where the guest never starts at all: no oracle "
                "file, no output, exit 0. It must be serialised.",
                "Interrupting one inside a private-display MOUNT NAMESPACE leaves "
                "processes in uninterruptible D state waiting on a FUSE connection "
                "whose daemon died with the namespace. They cannot be killed, and "
                "they poison that Proton prefix for every later run. proton-run is "
                "therefore never wrapped in a namespace here, and it gets a prefix "
                "of its own.",
            ],
            "why_sample_only": "Because of the four properties above, this layer is "
                               "baselined for a REPRESENTATIVE SAMPLE of specimens "
                               "rather than all of them. The full corpus is "
                               "baselined on native, wine and proton-wine.",
        }
    return records


# --------------------------------------------------------------------------
# Running one repeat of one specimen on one layer
# --------------------------------------------------------------------------

PROTON_DISPLAY = [None]
PROTON_XVFB = [None]


def start_corpus_display(num=96):
    """One X server, owned by this generation, in the HOST namespace, for
    proton-run only. No window is ever created on it by a console specimen, and it
    is not the developer's display. GUI specimens do NOT use it: they get the
    project's namespaced private display."""
    proc = subprocess.Popen(["Xvfb", ":%d" % num, "-screen", "0", "1024x768x24",
                             "-nolisten", "tcp"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    PROTON_DISPLAY[0] = ":%d" % num
    PROTON_XVFB[0] = proc
    return {"display": PROTON_DISPLAY[0], "pid": proc.pid, "alive": proc.poll() is None}


def stop_corpus_display():
    if PROTON_XVFB[0] is not None:
        PROTON_XVFB[0].terminate()
        try:
            PROTON_XVFB[0].wait(timeout=10)
        except subprocess.TimeoutExpired:
            PROTON_XVFB[0].kill()


DISPLAY_COUNTER = [110]
DISPLAY_LOCK = threading.Lock()


def next_display():
    with DISPLAY_LOCK:
        DISPLAY_COUNTER[0] += 1
        if DISPLAY_COUNTER[0] > 180:
            DISPLAY_COUNTER[0] = 111
        return DISPLAY_COUNTER[0]


def parse_oracle(text):
    kv, det, repeats = {}, [], []
    for line in text.split("\n"):
        if not line or "=" not in line:
            continue
        key, val = line.split("=", 1)
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        if key in kv and kv[key] != val:
            repeats.append(key)
        kv[key] = val
        if not key.startswith("OBS_"):
            det.append(line)
    return kv, det, sorted(set(repeats))


def stage_run_dir(spec, out, layer, repeat, support):
    rundir = os.path.join(out, "run", spec["id"], layer, "r%d" % repeat)
    if os.path.exists(rundir):
        shutil.rmtree(rundir)
    os.makedirs(rundir)
    for rel, content in spec["staged_files"].items():
        path = os.path.join(rundir, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", newline="\n") as f:
            f.write(content)
    exe = spec["build"]["target"]
    if layer == "native":
        exe = spec["native"]["target"]
        return rundir, exe
    if spec["stage"] == "bundle_wlib":
        # The property IS that the DLL sits beside the executable, so both are
        # copied into the run directory and nothing else is on the search path.
        shutil.copy2(exe, rundir)
        for lib in ("wlib.dll", "wlib32.dll"):
            src = os.path.join(out, "dll", lib)
            if os.path.exists(src):
                shutil.copy2(src, rundir)
        exe = os.path.join(rundir, os.path.basename(exe))
    elif spec["stage"] == "isolate_exe":
        shutil.copy2(exe, rundir)
        exe = os.path.join(rundir, os.path.basename(exe))
    elif spec["stage"] == "bundle_cxx_dlls":
        shutil.copy2(exe, rundir)
        for name in CXX_RUNTIME_DLLS:
            src = support["cxx_runtime_dlls"].get(name)
            if src and os.path.exists(src):
                shutil.copy2(src, rundir)
        exe = os.path.join(rundir, os.path.basename(exe))
    elif spec["stage"] in ("search_both", "search_alt_only"):
        # Two DLLs with the SAME NAME in two places. The "alt" one always goes in
        # altdir\; the "primary" one goes beside the executable ONLY when the
        # specimen is about to assert that the application directory wins. The
        # alt-only staging is what makes the SetDllDirectory and AddDllDirectory
        # specimens meaningful: without it the loader would find a DLL anyway and
        # the specimen would pass while proving nothing.
        shutil.copy2(exe, rundir)
        altdir = os.path.join(rundir, "altdir")
        os.makedirs(altdir, exist_ok=True)
        shutil.copy2(os.path.join(out, "dll", "search-alt", "wsearch.dll"), altdir)
        if spec["stage"] == "search_both":
            shutil.copy2(os.path.join(out, "dll", "search-primary", "wsearch.dll"),
                         rundir)
        exe = os.path.join(rundir, os.path.basename(exe))
    return rundir, exe


def run_once(spec, out, layer, rundir, exe, launch_index, display_helper):
    env = layer_env(layer, out, spec, rundir)
    cmd = layer_command(layer, exe, spec["argv"])
    display_num = None
    needs_display = spec["gui"]
    if needs_display and layer != "native":
        display_num = next_display()
        cmd = ["bash", display_helper, str(display_num)] + cmd
    else:
        # No display at all unless the specimen asked for one, so nothing can
        # reach the developer's desktop even by mistake.
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
    t0 = time.time()
    timed_out = False
    abandoned = None
    gate = (PROTON_LOCK if layer == "proton-run"
            else GUI_LOCK if (needs_display and layer != "native") else None)
    if gate:
        gate.acquire()
    if needs_display and layer in ("wine", "proton-wine"):
        # Start this GUI launch with no leftover Wine services from the previous
        # launch's display. See the comment on GUI_LOCK: they are per-prefix, they
        # keep X11 state, and a private display only exists for one launch.
        kenv = dict(BASE_ENV)
        kenv["WINEPREFIX"] = wine_prefix(layer, out, True)
        kenv["WINEDEBUG"] = "-all"
        sh([wineserver_for(layer), "-k"], env=kenv, timeout=60)
    proc = None
    pipe_held_open = False
    try:
        proc = subprocess.Popen(cmd, cwd=rundir, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        # Drain the pipes in threads and wait for the PROCESS, not for EOF on its
        # pipes. MEASURED, and the reason this is not communicate():
        #
        # a GUI tree under Proton's Wine occasionally leaves a Wine service
        # process (explorer.exe and friends) alive in the private display's
        # namespace after the guest tree has finished. That process INHERITED the
        # guest's stdout and stderr, so the pipes never reach EOF, and
        # communicate() -- which waits for EOF and not for the child -- sat there
        # for the full 300 s timeout on a run whose oracle files showed the entire
        # six-process tree had completed cleanly in about a second. One repeat in
        # five, so it would have surfaced later as a mystery flake.
        #
        # The process group must NOT be killed to break that: several specimens
        # DELIBERATELY leave a detached process running past the launcher's exit
        # and the generator inspects what it writes afterwards. Killing the group
        # would destroy exactly the evidence those specimens exist to produce.
        # So the readers are left to their fate as daemon threads and the run is
        # scored on the process's own exit.
        chunks = {"out": [], "err": []}

        def drain(stream, key):
            try:
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    chunks[key].append(block)
            except (ValueError, OSError):
                pass

        readers = [threading.Thread(target=drain, args=(proc.stdout, "out"),
                                    daemon=True),
                   threading.Thread(target=drain, args=(proc.stderr, "err"),
                                    daemon=True)]
        for t in readers:
            t.start()
        feeder = threading.Thread(
            target=lambda: (proc.stdin.write(spec["stdin"]), proc.stdin.close()),
            daemon=True)
        feeder.start()
        try:
            proc.wait(timeout=spec["timeout_s"])
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            try:
                # Briefly, then give up: a process wedged in uninterruptible D
                # state (see the proton-run findings) never dies, and waiting for
                # it would hang the whole generation.
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                abandoned = proc.pid
        # The guest is gone, so everything it ever wrote is already in the pipe.
        # Joining with a bound collects it; a join that times out means something
        # ELSE still holds the write end, which is recorded rather than waited on.
        for t in readers:
            t.join(timeout=30)
            if t.is_alive():
                pipe_held_open = True
        so = b"".join(chunks["out"])
        se = b"".join(chunks["err"])
        rc = proc.returncode
    finally:
        if gate:
            gate.release()
    duration = round((time.time() - t0) * 1000.0, 1)
    oracle_name = spec["oracle_file"] or (spec["id"] + ".oracle")
    oracle_path = os.path.join(rundir, oracle_name)
    oracle_text = ""
    if os.path.exists(oracle_path):
        with open(oracle_path, "r", errors="replace") as f:
            oracle_text = f.read()
    kv, det, repeated = parse_oracle(oracle_text)
    return {
        "launch_index": launch_index,
        "layer": layer,
        "command": cmd,
        "display": display_num,
        "exit_code": rc,
        "timed_out": timed_out,
        "abandoned_unkillable_pid": abandoned,
        # True when the guest exited but something still held the write end of
        # its stdout/stderr -- a lingering Wine service, usually. An observation
        # about the layer, never a verdict: everything the guest wrote was
        # already collected by the time this is decided.
        "stdio_pipe_still_held_after_exit": pipe_held_open,
        "duration_ms": duration,
        "oracle_file": oracle_name,
        "oracle_file_present": bool(oracle_text),
        "oracle": kv,
        "oracle_deterministic_lines": det,
        "oracle_repeated_keys": repeated,
        "observations": {k[4:]: v for k, v in kv.items() if k.startswith("OBS_")},
        "stdout_bytes": len(so),
        "stderr_bytes": len(se),
        "stdout_sha256": sha256_bytes(so),
        "stdout_head": so[:1024].decode("utf-8", "replace"),
        "stderr_head": se[:1024].decode("utf-8", "replace"),
    }


# --------------------------------------------------------------------------
# Verdict, per layer
# --------------------------------------------------------------------------

def verdict_for_layer(spec, layer, launches, post_state):
    d = spec["declared"]
    problems = []
    last = launches[-1]

    if last["timed_out"] and not d.get("timeout_allowed"):
        problems.append("%s: timed out after %.0fs" % (layer, spec["timeout_s"]))

    allowed = d.get("exit_one_of_by_layer", {}).get(layer)
    if allowed is not None:
        if last["exit_code"] not in allowed:
            problems.append("%s: exit code %r is none of the declared %r"
                            % (layer, last["exit_code"], allowed))
        return problems + _rest_of_checks(spec, layer, launches, post_state)
    want_exit = d["exit_code_by_layer"].get(layer, d["exit_code"])
    if d["nonzero_exit_required"]:
        if last["exit_code"] in (0, None):
            problems.append("%s: declared an abnormal termination, observed exit %r"
                            % (layer, last["exit_code"]))
    elif want_exit is not None and last["exit_code"] != want_exit:
        problems.append("%s: exit code declared %r, observed %r"
                        % (layer, want_exit, last["exit_code"]))

    return problems + _rest_of_checks(spec, layer, launches, post_state)


def _rest_of_checks(spec, layer, launches, post_state):
    d = spec["declared"]
    problems = []
    last = launches[-1]
    expect = dict(d["expect"])
    expect.update(d["expect_by_layer"].get(layer, {}))

    if expect and not last["oracle_file_present"]:
        problems.append("%s: no oracle file (%s) was produced at all"
                        % (layer, last["oracle_file"]))
    for key, want in expect.items():
        got = last["oracle"].get(key, "<absent>")
        if got != want:
            problems.append("%s: %s declared %r, observed %r" % (layer, key, want, got))

    for key, allowed in d["expect_one_of"].items():
        got = last["oracle"].get(key, "<absent>")
        if got not in allowed:
            problems.append("%s: %s observed %r, none of the declared %r"
                            % (layer, key, got, allowed))

    for key in d["expect_absent"]:
        if key in last["oracle"]:
            problems.append("%s: %s must NOT appear, observed %r"
                            % (layer, key, last["oracle"][key]))

    if d["requires_result_pass"]:
        result = last["oracle"].get("RESULT")
        if result != "PASS":
            problems.append("%s: RESULT is %r, expected PASS (the specimen's own "
                            "self-checks failed or it did not finish)" % (layer, result))

    # The identity oracle, enforced. A specimen must say WHICH specimen it is
    # from the value compiled into it, so a consumer can tell that without
    # trusting an environment variable a conforming runtime has to clear -- and,
    # here, so the oracle file lands where the runner looks for it.
    build_id = last["oracle"].get("FIXTURE_BUILD_ID")
    if build_id is None:
        if last["oracle_file_present"]:
            problems.append(
                "%s: no FIXTURE_BUILD_ID line: this specimen cannot be identified "
                "by anything that resets the environment, and FIXTURE_ID alone is "
                "not an identity oracle" % layer)
    else:
        want_build_id = d.get("build_id_expected") or spec["id"]
        if build_id != want_build_id:
            problems.append("%s: FIXTURE_BUILD_ID is %r, expected %r -- the "
                            "compiled-in identity does not match what this "
                            "binary was built as"
                            % (layer, build_id, want_build_id))

    for pair in d.get("equal_keys", []):
        a, b = pair
        va, vb = last["oracle"].get(a), last["oracle"].get(b)
        if va is None or vb is None or va != vb:
            problems.append("%s: %s and %s must be equal (got %r and %r)"
                            % (layer, a, b, va, vb))

    for key, seq in d.get("expect_sequence", {}).items():
        got = [x["oracle"].get(key) for x in launches]
        if got != seq:
            problems.append("%s: %s across launches declared %r, observed %r"
                            % (layer, key, seq, got))

    for name, needles in d["post_files"].items():
        content = post_state.get(name)
        if content is None:
            problems.append("%s: declared post-run file %s was never created"
                            % (layer, name))
            continue
        for needle in needles:
            if needle not in content:
                problems.append("%s: post-run file %s lacks %r" % (layer, name, needle))
    return problems


def settle_for(spec, rundir):
    """Wait for the work that continues after the launched process has exited.

    A FIXED settle is a race, not a margin. `pe-tree-gui-leaf` proved it: its
    window node holds a window for 2500 ms and then writes its terminal line, and
    with settle=6.0 it lost the FIRST of five identical repeats under Wine --
    cold-start cost landed the node's last write after the files were collected.
    The specimen then reported the host's warm-up as a missing post-run line, and
    a bigger number would only have moved the threshold.

    So where a specimen names a terminal line per post-run file, this waits for
    that line to APPEAR and treats settle_s as a CEILING. Nothing is weakened by
    it: the declaration is still that the file contains its declared lines, and if
    the work never finishes the wait expires and the specimen fails as it should.
    Specimens that name no terminal line keep the plain sleep.
    """
    ceiling = spec["settle_s"]
    if not ceiling:
        return
    until = spec["declared"].get("post_files_complete_when") or {}
    if not until:
        time.sleep(ceiling)
        return
    deadline = time.time() + ceiling
    while time.time() < deadline:
        if all(os.path.exists(os.path.join(rundir, name))
               and needle in open(os.path.join(rundir, name), "r",
                                  errors="replace").read()
               for name, needle in until.items()):
            time.sleep(0.3)      # let the writer close, not only finish writing
            return
        time.sleep(0.2)
    # Expired: collect whatever is there and let the declaration fail honestly.


# --------------------------------------------------------------------------
# Harness faults, as opposed to specimen outcomes
# --------------------------------------------------------------------------
#
# Some failures are not the program's, the declaration's or even the layer's --
# they are this harness's, and they are identifiable by an unmistakable message on
# stderr that no legitimate specimen can produce:
#
#   "wine client error ... Connection reset by peer"
#       the guest could not talk to its wineserver at all. MEASURED once in five
#       repeats: exit 1 after 4.8 ms with no oracle file, on a different specimen
#       in each generation. A wineserver shutting down as its last client leaves
#       can be mid-shutdown when the next specimen connects.
#
#   "X Error of failed request ... X_UnmapWindow"
#       Xlib's default error handler exited the guest MID-RUN, leaving a truncated
#       oracle. Caused by this harness giving one Wine prefix a different private
#       X display per launch while that prefix's services keep X11 state -- which
#       is why GUI specimens now get a prefix of their own and are serialised.
#
# Such an attempt is DISCARDED AND RECORDED, never scored, and never silent: every
# discarded attempt is kept in the repeat record with its stderr, counted in
# counts.harness_fault_retries, and printed at the end of the run. A retry is
# allowed only for a harness fault; a specimen that fails, crashes, times out or
# writes nothing for its OWN reasons is never retried, because that is the
# measurement.
HARNESS_FAULT_MARKERS = (
    "wine client error",
    "Connection reset by peer",
    "X Error of failed request",
    "PD_UNAVAILABLE",
)
HARNESS_FAULT_ATTEMPTS = 3
HARNESS_FAULTS = []          # every discarded attempt, corpus-wide, never silent


def harness_fault(launch):
    text = (launch.get("stderr_head") or "") + (launch.get("stdout_head") or "")
    for marker in HARNESS_FAULT_MARKERS:
        if marker in text:
            return marker
    return None


def collect_post(spec, rundir):
    state = {}
    for name in spec["declared"]["post_files"]:
        path = os.path.join(rundir, name)
        if os.path.exists(path):
            with open(path, "r", errors="replace") as f:
                state[name] = f.read()
    return state


def process(spec, out, layers, repeats, support, display_helper):
    rec = {k: v for k, v in spec.items() if k != "stdin"}
    rec["stdin"] = {"bytes": len(spec["stdin"]),
                    "sha256": sha256_bytes(spec["stdin"]) if spec["stdin"] else None}
    rec["source"] = {
        "files": spec["sources"],
        "sha256": {s: sha256_file(os.path.join(SPECS, s)) for s in spec["sources"]},
        "oracle_header_sha256": sha256_file(os.path.join(SPECS, "oracle_win.h")),
    }
    build = build_one(spec, out)
    spec["build"] = build
    rec["build"] = build
    if not build["ok"]:
        rec["verdict"] = {"status": "build-failed",
                          "problems": [build["warnings"][-1500:] or "compiler failed"]}
        rec["binary"] = None
        rec["baselines"] = None
        return rec

    actual_pe = pe_facts(build["target"])
    pe_problems = check_pe(spec["declared"]["pe"], actual_pe)
    rec["binary"] = {"path": build["target"], "sha256": sha256_file(build["target"]),
                     "size_bytes": os.path.getsize(build["target"]),
                     "pe": actual_pe, "declared_pe_problems": pe_problems}

    chosen = [l for l in spec["layers"] if l in layers]
    if "native" in chosen:
        spec["native"] = build_native_twin(spec, out)
        rec["native_build"] = spec["native"]
        if not spec["native"]["ok"]:
            chosen = [l for l in chosen if l != "native"]
            pe_problems.append("native twin failed to build: "
                               + spec["native"]["warnings"][-300:])
    rec["layers_run"] = chosen

    problems = list(pe_problems)
    # A specimen that ran on NO layer has no baseline, and a specimen with no
    # baseline is not evidence -- it cannot distinguish a working program from a
    # broken one, because nothing was observed. Without this, the layer loop
    # below simply does not execute, `problems` stays empty, and the specimen is
    # admitted as `baseline-ok`: zero observations and all-observations-clean
    # render identically. An evidence audit found exactly that here --
    # pe-io-stdin-under-proton-run was recorded baseline-ok with `layers_run: []`
    # and `baselines: {}`, and it had no run directory on disk, so the corpus
    # held 71 directories for 72 specimens and nothing said so.
    #
    # This is the same defect the corpus keeps finding in other people's code,
    # and it was in mine: an emptiness that looks like success.
    if not chosen:
        problems.append(
            "no layer was run: spec.layers=%r intersected with the requested "
            "layers gave nothing, so this specimen has NO baseline and cannot be "
            "evidence. A specimen that was never executed must not be admitted."
            % (spec["layers"],))
    baselines = {}
    for layer in chosen:
        repeat_records, verdicts = [], []
        warmup = None
        if spec["declared"].get("warmup_launch") and layer != "native":
            # One throwaway launch, so the measured repeats see a warm prefix.
            wdir, wexe = stage_run_dir(spec, out, layer, 999, support)
            w = run_once(spec, out, layer, wdir, wexe, 0, display_helper)
            warmup = {"duration_ms": w["duration_ms"], "exit_code": w["exit_code"],
                      "timed_out": w["timed_out"],
                      "why": "a cold Wine prefix makes the first GUI launch of a "
                             "process take minutes and sometimes fail to exit at "
                             "all; the corpus measures steady state and records "
                             "this cost separately"}
            shutil.rmtree(wdir, ignore_errors=True)
        for repeat in range(repeats):
            discarded = []
            for attempt in range(HARNESS_FAULT_ATTEMPTS):
                rundir, exe = stage_run_dir(spec, out, layer, repeat, support)
                launches = [run_once(spec, out, layer, rundir, exe, i, display_helper)
                            for i in range(spec["runs"])]
                settle_for(spec, rundir)
                post = collect_post(spec, rundir)
                fault = next((harness_fault(l) for l in launches
                              if harness_fault(l)), None)
                if not fault or attempt == HARNESS_FAULT_ATTEMPTS - 1:
                    break
                # A fault in THIS harness, not an outcome of the specimen. The
                # attempt is thrown away and kept: see HARNESS_FAULT_MARKERS.
                discarded.append({
                    "attempt": attempt, "marker": fault,
                    "exit_codes": [l["exit_code"] for l in launches],
                    "duration_ms": [l["duration_ms"] for l in launches],
                    "oracle_keys": [len(l["oracle"]) for l in launches],
                    "stderr_head": launches[-1]["stderr_head"][:600],
                })
                HARNESS_FAULTS.append({"specimen": spec["id"], "layer": layer,
                                       "repeat": repeat, "attempt": attempt,
                                       "marker": fault})
            verdicts.append(verdict_for_layer(spec, layer, launches, post))
            repeat_records.append({
                "repeat": repeat, "run_dir": rundir, "launches": launches,
                "post_run_files": post,
                "discarded_harness_fault_attempts": discarded,
                "run_dir_listing": sorted(os.listdir(rundir))[:40],
            })
        det = [r["launches"][-1]["oracle_deterministic_lines"] for r in repeat_records]
        stable = all(x == det[0] for x in det)
        unstable_lines = []
        if not stable:
            base = set(det[0])
            for other in det[1:]:
                unstable_lines += [l for l in other if l not in base]
                unstable_lines += [l for l in det[0] if l not in set(other)]
        exits = sorted({r["launches"][-1]["exit_code"] for r in repeat_records},
                       key=lambda x: (x is None, x))  # a timeout gives None
        baselines[layer] = {
            "repeats": repeat_records,
            "repeat_count": repeats,
            "deterministic_across_repeats": stable,
            "unstable_lines": sorted(set(unstable_lines))[:20],
            "exit_codes_seen": exits,
            "exit_code_stable": len(exits) == 1,
            "duration_ms_observed": [r["launches"][-1]["duration_ms"] for r in repeat_records],
            "stdio_observable": layer in LAYERS_WITH_STDIO,
            "warmup_launch": warmup,
            "verdict_problems": verdicts[0],
        }
        problems += verdicts[0]
        expected_instability = spec["declared"].get("instability_expected")
        baselines[layer]["instability_expected"] = expected_instability
        if not stable and not expected_instability:
            problems.append("%s: deterministic output NOT stable across %d repeats"
                            % (layer, repeats))
        if len(exits) != 1 and not expected_instability:
            problems.append("%s: exit code varied across repeats: %r" % (layer, exits))
    rec["baselines"] = baselines
    if not chosen:
        # Never run, because the only layer it declares was not requested or
        # cannot be baselined on this host. That is neither a pass nor a failure
        # of the specimen, and calling it either would be a lie: `baseline-ok`
        # was the old answer and it hid the specimen entirely, while
        # `baseline-mismatch` would blame a fixture that was never given a
        # chance. It is BLOCKED, it is counted as blocked, and it is printed.
        rec["verdict"] = {
            "status": "blocked",
            "problems": problems,
            "blocked_reason":
                "declares layers %r; none of them was run, so this specimen has "
                "no baseline and is not evidence for anything. It is kept "
                "because the layer it needs may become baselinable later."
                % (spec["layers"],)}
        return rec
    rec["verdict"] = {"status": "baseline-ok" if not problems else "baseline-mismatch",
                      "problems": problems}
    return rec


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def cross_layer_report(rec):
    """Where two layers disagree about a deterministic line, that difference is a
    recorded PROPERTY OF THE LAYERS, not a failure. It is kept separate from the
    verdict on purpose: a Wine-versus-Proton difference must never be mistaken
    later for something .LEXE did."""
    if not rec.get("baselines"):
        return None
    lines = {}
    for layer, base in rec["baselines"].items():
        if base["repeats"]:
            lines[layer] = base["repeats"][0]["launches"][-1]["oracle_deterministic_lines"]
    if len(lines) < 2:
        return None
    reference = "native" if "native" in lines else ("wine" if "wine" in lines
                                                    else sorted(lines)[0])
    report = {"reference_layer": reference, "agreeing_layers": [], "differences": {}}
    for layer, det in lines.items():
        if layer == reference:
            continue
        base = set(lines[reference])
        only_here = [l for l in det if l not in base]
        only_ref = [l for l in lines[reference] if l not in set(det)]
        if not only_here and not only_ref:
            report["agreeing_layers"].append(layer)
        else:
            report["differences"][layer] = {
                "only_in_" + layer: only_here[:20],
                "only_in_" + reference: only_ref[:20],
            }
    exits = {layer: base["exit_codes_seen"] for layer, base in rec["baselines"].items()}
    report["exit_codes_by_layer"] = exits
    report["exit_codes_agree"] = len({tuple(v) for v in exits.values()}) == 1
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/lexe-workloads-pe")
    ap.add_argument("--only", default=None, help="substring filter on fixture id")
    ap.add_argument("--layers", default="native,wine,proton-wine",
                    help="proton-run is NOT a default: on this host Proton's own "
                         "launcher cannot be baselined (see DEFAULT_LAYERS_NOTE). "
                         "Pass it explicitly to try it elsewhere.")
    ap.add_argument("--repeats", type=int, default=5,
                    help="how many times to repeat each baseline (stability)")
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    layers = [l.strip() for l in args.layers.split(",") if l.strip()]

    global TOOL_VERSIONS, HOST
    HOST = host_facts()
    TOOL_VERSIONS = {}
    absent = []
    for tc in TOOLCHAINS.values():
        for key in ("cc", "cxx"):
            binary = tc[key]
            if binary not in TOOL_VERSIONS:
                TOOL_VERSIONS[binary] = tool_version(binary)
                if TOOL_VERSIONS[binary] == "ABSENT":
                    absent.append(binary)
    TOOL_VERSIONS["wine"] = tool_version("wine")

    t0 = time.time()
    support = build_support(out)
    display_helper = write_display_helper(out)

    chosen = [s for s in SPECIMENS if not args.only or args.only in s["id"]]

    # A prefix has to exist before anything can run in it, and creating one is
    # slow (Wine ~35s the first time). Build one probe binary first so the Proton
    # prefix can be created with a real executable.
    probe = [s for s in chosen if s["stage"] == "plain" and s["language"] == "c"]
    probe_build = build_one(probe[0], out) if probe else None
    probe_exe = probe_build["target"] if probe_build and probe_build["ok"] else None
    layer_records = setup_layers(out, layers, probe_exe)
    setup_seconds = round(time.time() - t0, 1)

    results = []
    with futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {pool.submit(process, s, out, layers, args.repeats, support,
                            display_helper): s for s in chosen}
        for fut in futures.as_completed(futs):
            spec = futs[fut]
            try:
                rec = fut.result()
            except Exception as exc:
                rec = {"id": spec["id"],
                       "verdict": {"status": "generator-error", "problems": [repr(exc)]}}
            rec["cross_layer"] = cross_layer_report(rec)
            results.append(rec)
            if not args.quiet:
                v = rec.get("verdict", {})
                print("%-18s %s" % (v.get("status", "?"), rec["id"]))
                for p in v.get("problems", [])[:8]:
                    print("                   ! %s" % p)
    results.sort(key=lambda r: r["id"])
    elapsed = round(time.time() - t0, 1)

    # Differential agreement, as in the ELF corpus.
    by_rid = {r["id"]: r for r in results}
    divergences = []
    for r in results:
        base = by_rid.get(r.get("differential_of"))
        if not base or not r.get("baselines") or not base.get("baselines"):
            continue
        shared = [l for l in r["baselines"] if l in base["baselines"]]
        diffs = {}
        for layer in shared:
            def det(rec):
                return [ln for ln in
                        rec["baselines"][layer]["repeats"][0]["launches"][-1]
                        ["oracle_deterministic_lines"]
                        # Both identity lines, for two different reasons:
                        # FIXTURE_ID is set per specimen by the runner, and
                        # FIXTURE_BUILD_ID is compiled in, so a differential --
                        # a different binary by definition -- must differ in it.
                        if not ln.startswith(("FIXTURE_ID=",
                                              "FIXTURE_BUILD_ID="))]
            a, b = det(base), det(r)
            only_b = [l for l in b if l not in set(a)]
            only_a = [l for l in a if l not in set(b)]
            if only_a or only_b:
                diffs[layer] = {"only_in_differential": only_b[:20],
                                "only_in_base": only_a[:20]}
        r["differential_agreement"] = {"base": base["id"], "agrees": not diffs,
                                      "differences": diffs}
        if diffs:
            divergences.append(r["id"])

    counts = {}
    for r in results:
        counts[r["verdict"]["status"]] = counts.get(r["verdict"]["status"], 0) + 1
    unstable = [r["id"] for r in results if r.get("baselines")
                and any(not b["deterministic_across_repeats"]
                        for b in r["baselines"].values())]
    layer_disagreements = {r["id"]: r["cross_layer"]["differences"]
                           for r in results
                           if r.get("cross_layer") and r["cross_layer"]["differences"]}

    index = {
        "schema": "lexe.workload.pe-index/1",
        "schema_notes": {
            "declared": "hand-written before the specimen was ever run; the "
                        "generator checks the observation against it",
            "baselines": "one cell PER TRANSLATION LAYER, each with every repeat, "
                         "recorded as the reference for any later indirect run",
            "oracle_file": "the primary artifact: every specimen writes its oracle "
                           "to a FILE as well as to the stream, because under "
                           "proton-run the stream does not reach the caller",
            "oracle_deterministic_lines": "every oracle line whose key does not "
                                          "start with OBS_; compare these exactly",
            "observations": "OBS_ values are environment-dependent, including every "
                            "duration; never a failure on their own",
            "cross_layer": "where layers disagree. A Wine-versus-Proton difference "
                           "is a property of the layers and is NOT a failure; it is "
                           "kept out of the verdict so it can never later be "
                           "mistaken for something .LEXE did",
            "deterministic_across_repeats": "whether the deterministic lines were "
                                            "identical across every repeat. A "
                                            "specimen that is deterministic once "
                                            "and not five times is worse than one "
                                            "known to be nondeterministic",
            "verdict.status": "baseline-ok means admitted to the corpus for every "
                              "layer it declares; baseline-mismatch means the "
                              "FIXTURE or its declaration is wrong",
        },
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generator": {"file": os.path.basename(__file__),
                      "sha256": sha256_file(os.path.abspath(__file__)),
                      "specs_dir": SPECS,
                      "wall_seconds": elapsed,
                      "setup_seconds": setup_seconds,
                      "jobs": args.jobs,
                      "repeats": args.repeats},
        "host": HOST,
        "reproducible_link_flags": LINK_REPRODUCIBLE,
        "reproducibility_note": "Two PE builds of one source differ in exactly two "
                                "bytes without --no-insert-timestamp: the PE "
                                "TimeDateStamp. With it, every binary in this corpus "
                                "is byte-identical between independent generations, "
                                "verified under gcc x86-64, gcc i686 and clang.",
        "toolchains": {k: {"cc": v["cc"], "cxx": v["cxx"], "opt": v["opt"],
                           "target": v["target"], "extra": v["extra"],
                           "cc_version": TOOL_VERSIONS.get(v["cc"]),
                           "cxx_version": TOOL_VERSIONS.get(v["cxx"])}
                       for k, v in TOOLCHAINS.items()},
        "absent_toolchains": sorted(set(absent)),
        "layers": layer_records,
        "layers_selected": layers,
        "layers_implemented": ALL_LAYERS,
        "default_layers_note": DEFAULT_LAYERS_NOTE,
        "private_display": {
            "helper": PD_LIB,
            "wrapper": display_helper,
            "policy": "GUI specimens run ONLY on a private namespaced X server. No "
                      "automated test may put a window on the developer's desktop; "
                      "every other specimen runs with DISPLAY unset entirely.",
        },
        "corpus_root": out,
        "support_binaries": support,
        "counts": {
            "specimens": len(results),
            "differential_specimens": sum(1 for r in results if r.get("differential_of")),
            "differential_divergences": len(divergences),
            "unstable_specimens": len(unstable),
            "specimens_with_layer_differences": len(layer_disagreements),
            "baseline_runs": sum(len(b["repeats"]) * max(1, r.get("runs", 1))
                                 for r in results if r.get("baselines")
                                 for b in r["baselines"].values()),
            "harness_fault_retries": len(HARNESS_FAULTS),
            **counts,
        },
        "harness_faults": HARNESS_FAULTS,
        "harness_fault_markers": list(HARNESS_FAULT_MARKERS),
        "harness_fault_note":
            "An attempt DISCARDED because this harness failed, not the specimen and "
            "not the declaration: the guest could not reach its wineserver, or "
            "Xlib's default error handler exited it mid-run. Each one is kept with "
            "its stderr in the repeat record and counted here, so a retry can never "
            "be silent. A specimen that fails, crashes, times out or writes nothing "
            "for its OWN reasons is never retried -- that is the measurement.",
        "families": sorted({r.get("family", "?") for r in results}),
        "unstable_specimens": unstable,
        "differential_divergences": divergences,
        "layer_differences": layer_disagreements,
        "specimens": results,
    }
    index_path = os.path.join(out, "index.json")
    with open(index_path, "w") as f:
        json.dump(index, f, indent=1, sort_keys=False)

    stop_corpus_display()

    # Leave no wineserver behind.
    for prefix, server in ((os.path.join(out, "prefix-wine"), "wineserver"),
                           (os.path.join(out, "prefix-wine-gui"), "wineserver"),
                           (os.path.join(out, "prefix-protonwine"),
                            wineserver_for("proton-wine")),
                           (os.path.join(out, "prefix-protonwine-gui"),
                            wineserver_for("proton-wine")),
                           (os.path.join(out, "prefix-protonrun", "pfx"),
                            "wineserver")):
        if os.path.isdir(prefix):
            env = dict(BASE_ENV)
            env["WINEPREFIX"] = prefix
            sh([server, "-k"], env=env, timeout=60)

    print("\n%d specimens, %s, repeats=%d, %.1fs -> %s"
          % (len(results), ", ".join("%s=%d" % kv for kv in sorted(counts.items())),
             args.repeats, elapsed, index_path))
    if HARNESS_FAULTS:
        print("HARNESS FAULTS RETRIED (%d, discarded and recorded, not specimen "
              "outcomes): %s" % (len(HARNESS_FAULTS),
                                 ", ".join(sorted({"%s/%s[%s]" % (f["specimen"],
                                                                  f["layer"],
                                                                  f["marker"])
                                                   for f in HARNESS_FAULTS}))))
    if unstable:
        print("UNSTABLE ACROSS REPEATS (%d): %s" % (len(unstable), ", ".join(unstable)))
    if divergences:
        print("DIFFERENTIAL DIVERGENCE (%d): %s" % (len(divergences), ", ".join(divergences)))
    if layer_disagreements:
        print("LAYER DIFFERENCES (recorded as properties, not failures) in %d specimens"
              % len(layer_disagreements))
    # BLOCKED specimens are named out loud rather than folded into the total.
    # A count that reads "148 specimens, baseline-ok=147, blocked=1" is honest;
    # one that reads "148 baseline-ok" while one of them never ran is not, and
    # that is precisely the defect an evidence audit found here.
    blocked = [r["id"] for r in results if r["verdict"]["status"] == "blocked"]
    if blocked:
        print("BLOCKED -- never run, therefore not evidence (%d): %s"
              % (len(blocked), ", ".join(blocked)))
        for r in results:
            if r["verdict"]["status"] == "blocked":
                print("    %s: %s" % (r["id"], r["verdict"]["blocked_reason"]))
    ok = counts.get("baseline-ok", 0)
    return 0 if ok + len(blocked) == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())

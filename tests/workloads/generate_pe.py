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


def sh(cmd, timeout=300, **kw):
    """Run a command and never wait forever. A hung toolchain or a hung
    translation layer is a finding, not something to sit through."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, **kw)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(
            cmd, 124, e.stdout or "",
            (e.stderr or "") + chr(10) + "[generator] timed out after " + str(timeout) + "s")


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
DLLS = [
    {"name": "wlib.dll", "src": "wlib.c", "toolchain": "mingw64-O2", "implib": "libwlib.a"},
    {"name": "wlib32.dll", "src": "wlib.c", "toolchain": "mingw32-O2", "implib": None},
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
  expect={"SLEEP_REQUESTED_MS": "500", "SLEPT_AT_LEAST_REQUESTED": "yes",
          "DURATION_CLASS": "sub-second"})
S("pe-run-bounded-3s", "w_longrun.c", "outcome", "a long-running process",
  argv=["3000"], duration="seconds", timeout=180.0,
  expect={"SLEEP_REQUESTED_MS": "3000", "SLEPT_AT_LEAST_REQUESTED": "yes",
          "DURATION_CLASS": "seconds"})
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

TREE_SOURCES = ["t_launcher.c", "t_bootstrap.c", "t_main.c", "t_helper.c",
                "t_worker.c", "t_crash_handler.c"]


def tree(fid, mode, prop, **kw):
    return S(fid, TREE_SOURCES, "process-tree", prop, stage="tree",
             argv=[mode], oracle_file="t_launcher.oracle",
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
     settle=6.0, timeout=180.0,
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
     settle=6.0, timeout=180.0,
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
     settle=7.0, timeout=180.0,
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
     settle=8.0, timeout=180.0,
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


def compile_cmd(spec, out, target):
    tc = TOOLCHAINS[spec["toolchain"]]
    cxx = spec["language"] == "c++"
    driver = tc["cxx"] if cxx else tc["cc"]
    flags = (COMMON_CXX if cxx else COMMON_C) + tc["opt"] + tc["extra"]
    srcs = [os.path.join(SPECS, s) for s in spec["sources"]]
    cmd = [driver] + flags + srcs + ["-o", target] + spec["cflags"] + LINK_REPRODUCIBLE
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
        target = os.path.join(dlldir, lib["name"])
        cmd = ([tc["cc"]] + COMMON_C + tc["opt"] + ["-shared",
                                                    os.path.join(SPECS, lib["src"]),
                                                    "-o", target] + LINK_REPRODUCIBLE)
        if lib["implib"]:
            cmd += ["-Wl,--out-implib," + os.path.join(dlldir, lib["implib"])]
        r = sh(cmd)
        record["dlls"].append({"name": lib["name"], "toolchain": lib["toolchain"],
                               "command": " ".join(cmd), "ok": r.returncode == 0,
                               "stderr": r.stderr.strip()[:1000],
                               "sha256": sha256_file(target) if os.path.exists(target) else None})
    treedir = os.path.join(out, "tree")
    os.makedirs(treedir, exist_ok=True)
    tc = TOOLCHAINS["mingw64-O2"]
    for src in TREE_SOURCES:
        target = os.path.join(treedir, src[:-2] + ".exe")
        cmd = ([tc["cc"]] + COMMON_C + tc["opt"] + [os.path.join(SPECS, src),
                                                    "-o", target] + LINK_REPRODUCIBLE)
        r = sh(cmd)
        record["tree"].append({"name": os.path.basename(target),
                               "command": " ".join(cmd), "ok": r.returncode == 0,
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
    cmd = compile_cmd(spec, out, target)
    t0 = time.time()
    r = sh(cmd)
    return {"toolchain": spec["toolchain"], "compiler": cmd[0],
            "compiler_version": TOOL_VERSIONS.get(cmd[0], "?"),
            "flags": cmd[1:], "command": " ".join(cmd),
            "ok": r.returncode == 0 and os.path.exists(target),
            "seconds": round(time.time() - t0, 2),
            "warnings": r.stderr.strip()[:4000], "target": target,
            "shared_build": False}


def build_native_twin(spec, out):
    """The same source built as a Linux ELF, for the reference cell. Only the
    portable specimens can have one; anything that includes windows.h cannot, and
    says so rather than pretending."""
    target = os.path.join(out, "native", spec["id"])
    os.makedirs(os.path.dirname(target), exist_ok=True)
    cmd = (["gcc"] + COMMON_C + ["-O2"] + [os.path.join(SPECS, s) for s in spec["sources"]]
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


def layer_env(layer, out, spec, rundir):
    env = dict(BASE_ENV)
    env["FIXTURE_ID"] = spec["id"]
    env["WINEDEBUG"] = "-all"
    env["WINEDLLOVERRIDES"] = "mscoree,mshtml="
    if layer == "wine":
        env["WINEPREFIX"] = os.path.join(out, "prefix-wine")
    elif layer == "proton-wine":
        env["WINEPREFIX"] = os.path.join(out, "prefix-protonwine")
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
        records["wine"] = {
            "kind": "system wine, directly",
            "binary": "wine", "version": TOOL_VERSIONS.get("wine"),
            "prefix": env["WINEPREFIX"],
            "prefix_creation_seconds": round(time.time() - t0, 1),
            "wineboot_ok": boot.returncode == 0,
            "configuration": [WINEDBG_KEY + " ShowCrashDialog = 0 (no debugger on "
                              "an unhandled fault, so a crash dies instead of hanging)"],
            "configuration_ok": reg.returncode == 0,
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
        records["proton-wine"] = {
            "kind": "the wine binary inside Proton, run directly, headless",
            "binary": PROTON_WINE,
            "proton_build": HOST["proton_version"],
            "prefix": pfxenv["WINEPREFIX"],
            "prefix_creation_seconds": round(time.time() - t0, 1),
            "wineboot_ok": boot.returncode == 0,
            "configuration": [WINEDBG_KEY + " ShowCrashDialog = 0"],
            "configuration_ok": reg.returncode == 0,
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
    gate = PROTON_LOCK if layer == "proton-run" else None
    if gate:
        gate.acquire()
    proc = None
    try:
        proc = subprocess.Popen(cmd, cwd=rundir, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            so, se = proc.communicate(input=spec["stdin"], timeout=spec["timeout_s"])
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
                so, se = proc.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                abandoned = proc.pid
                so, se = b"", b""
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
            rundir, exe = stage_run_dir(spec, out, layer, repeat, support)
            launches = [run_once(spec, out, layer, rundir, exe, i, display_helper)
                        for i in range(spec["runs"])]
            if spec["settle_s"]:
                time.sleep(spec["settle_s"])
            post = collect_post(spec, rundir)
            verdicts.append(verdict_for_layer(spec, layer, launches, post))
            repeat_records.append({
                "repeat": repeat, "run_dir": rundir, "launches": launches,
                "post_run_files": post,
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
                        if not ln.startswith("FIXTURE_ID=")]
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
            **counts,
        },
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
    for prefix in (os.path.join(out, "prefix-wine"),
                   os.path.join(out, "prefix-protonwine"),
                   os.path.join(out, "prefix-protonrun", "pfx")):
        if os.path.isdir(prefix):
            env = dict(BASE_ENV)
            env["WINEPREFIX"] = prefix
            sh(["wineserver", "-k"], env=env)

    print("\n%d specimens, %s, repeats=%d, %.1fs -> %s"
          % (len(results), ", ".join("%s=%d" % kv for kv in sorted(counts.items())),
             args.repeats, elapsed, index_path))
    if unstable:
        print("UNSTABLE ACROSS REPEATS (%d): %s" % (len(unstable), ", ".join(unstable)))
    if divergences:
        print("DIFFERENTIAL DIVERGENCE (%d): %s" % (len(divergences), ", ".join(divergences)))
    if layer_disagreements:
        print("LAYER DIFFERENCES (recorded as properties, not failures) in %d specimens"
              % len(layer_disagreements))
    return 0 if counts.get("baseline-ok", 0) == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())

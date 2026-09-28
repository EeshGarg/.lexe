#!/usr/bin/env python3
"""Portable-source workload factory for .LEXE.

The third payload kind. A `native` package ships a compiled ELF and a `windows`
package ships a PE; a `portable` package ships SOURCE, and the machine that
installs it compiles it. Nothing in the ELF or PE corpora exercises that, because
in both of them the compiler ran here, on my machine, before the package existed.

So this factory manufactures RECIPES, and the artifact it records a baseline for
is the BUILD as much as the program:

    recipe (manifest + source + build file)
        -> assembled package
        -> DIRECT BUILD, outside .LEXE, in a clean environment
        -> what the build produced, read out of the file with readelf and file(1)
        -> DIRECT EXECUTION of the product, in the tree that built it
        -> DIRECT EXECUTION again, from a different directory, with the build
           tree renamed away
        -> only then admitted to the corpus

The last two steps are not decoration. A build that bakes an absolute path into
its product -- and the ordinary `-Wl,-rpath,$(pwd)/../lib` in a Makefile does
exactly that -- produces something that runs perfectly in the directory it was
built in and cannot start anywhere else. Measuring only the first run would
record that specimen as healthy.

Nothing here knows anything about .LEXE. The manifests are validated against
schema/lexe-manifest-0.1.schema.json with jsonschema, which is an independent
check that the package is well formed; whether .LEXE should accept, reject or
rewrite any of these recipes is not a question this file answers.

Usage (inside WSL):
    python3 generate_portable.py [--out DIR] [--only SUBSTR] [--jobs N]

Build products land in --out (default /tmp/lexe-workloads-portable), never in
the repository.
"""

import argparse
import concurrent.futures as futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RECIPES = os.path.join(HERE, "specs_portable")
DEFAULT_SCHEMA = os.path.abspath(
    os.path.join(HERE, "..", "..", "schema", "lexe-manifest-0.1.schema.json"))

BUILD_TIMEOUT_S = 600.0
RUN_TIMEOUT_S = 120.0


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
    """Best-effort version string. `sh` is in several recipes' declared toolchain
    and does not understand --version at all (dash answers "Illegal option --"),
    so a refusal is reported as one rather than recorded as if it were a version."""
    r = sh([binary, "--version"])
    text = r.stdout or r.stderr
    first = text.splitlines()[0].strip() if text else ""
    if not first or "llegal option" in first or "nvalid option" in first \
       or "nrecognized option" in first:
        return "present; does not report a version"
    return first


def host_facts():
    return {
        "uname": sh(["uname", "-srvmo"]).stdout.strip(),
        "machine": sh(["uname", "-m"]).stdout.strip(),
        "distro": next((l.split("=", 1)[1].strip().strip('"')
                        for l in open("/etc/os-release") if l.startswith("PRETTY_NAME=")), "?"),
        "libc": (sh(["ldd", "--version"]).stdout.splitlines() or ["?"])[0].strip(),
        "nproc": int(sh(["nproc"]).stdout.strip() or 1),
        "page_size": os.sysconf("SC_PAGESIZE"),
        "binfmt_misc_registered": sorted(os.listdir("/proc/sys/fs/binfmt_misc"))
                                  if os.path.isdir("/proc/sys/fs/binfmt_misc") else None,
    }


def elf_facts(path):
    """What the built file actually is, read out of it rather than assumed."""
    out = {}
    f = sh(["file", "-b", path])
    out["file_says"] = f.stdout.strip()
    h = sh(["readelf", "-hdW", path])
    out["is_elf"] = h.returncode == 0
    if h.returncode != 0:
        out["readelf_says"] = (h.stderr or h.stdout).strip()[:200]
        return out
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
    out["rpath_tag"] = "DT_RPATH" if rp else ("DT_RUNPATH" if ru else None)
    p = sh(["readelf", "-lW", path])
    mi = re.search(r"\[Requesting program interpreter: ([^\]]+)\]", p.stdout)
    out["interpreter"] = mi.group(1) if mi else None
    s = sh(["readelf", "-SW", path])
    out["has_symtab"] = ".symtab" in s.stdout
    out["pie"] = out.get("e_type") == "DYN"
    return out


def classify_product(facts):
    """host-elf-exec / elf-shared-object / pe / other -- decided from file(1) and
    readelf, which are witnesses outside this program, not from the flags the
    recipe used."""
    says = (facts.get("file_says") or "").lower()
    if not facts.get("is_elf"):
        if "pe32" in says or "ms windows" in says:
            return "pe"
        if says.startswith("ascii text") or "script" in says:
            return "script"
        return "other"
    if "shared object" in says:
        return "elf-shared-object"
    if "executable" in says:
        return "host-elf-exec"
    if "relocatable" in says:
        return "elf-object"
    return "elf-other"


def ldd_says(path):
    r = sh(["ldd", path])
    return {"exit": r.returncode,
            "stdout": r.stdout.strip()[:2000],
            "stderr": r.stderr.strip()[:500]}


def tree_files(root):
    """Every regular file under root, relative path -> (size, sha256)."""
    out = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, root)
            out[rel] = {"size": os.path.getsize(full), "sha256": sha256_file(full)}
    return out


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


# --------------------------------------------------------------------------
# The recipe table.
#
# Every `expect_*` field is a DECLARATION written before the recipe was ever
# built. The generator builds it, reads the product with readelf and file(1),
# runs it twice, and reports every disagreement. A disagreement means the
# DECLARATION was wrong, which is the only way this exercise is worth anything:
# the rpath predictions below are the whole point of the family, and getting one
# wrong is a finding rather than an embarrassment.
#
#   {SRCDIR}  in expect_runpath is substituted with the absolute source
#             directory the build ran in, because that is what an idiom like
#             $(CURDIR) resolves to and the value is not knowable until then.
# --------------------------------------------------------------------------

RECIPES = []


def P(rid, recipe_dir, entrypoint, system, **kw):
    spec = {
        "id": rid,
        "family": "portable",
        "recipe_dir": recipe_dir,
        "source_dir": kw.get("source_dir", "src"),
        "entrypoint": entrypoint,
        "arguments": list(kw.get("arguments", [])),
        "build_system": system,
        "build_command": list(kw.get("command", [])) or None,
        "toolchain": list(kw["toolchain"]),
        "architectures": list(kw.get("architectures", ["x86_64", "aarch64"])),
        "makefile_variant": kw.get("makefile_variant"),
        # A file copied over one of the payload's own before the build, so a
        # family of recipes can share one source tree and differ only in its
        # build file. `makefile_variant` is the same mechanism with
        # variant_dest="Makefile"; `variant_dest` generalises it to CMakeLists.txt.
        "variant_dest": kw.get("variant_dest", "Makefile"),
        # Extra environment for the DIRECT build, on top of the deliberately
        # small default. Recorded in build.env, so a recipe that only builds
        # because of it is visible rather than implied. Every recipe here still
        # builds with this empty -- that is a separate declaration, not a
        # fallback -- and the pair of env_flags recipes exists to show both.
        "build_env_extra": dict(kw.get("build_env_extra", {})),
        # cmake-only knobs. The cmake argv sequence is THIS generator's choice
        # (see build_commands), so these are recorded as part of it.
        "cmake_defines": list(kw.get("cmake_defines", [])),
        "cmake_install": bool(kw.get("cmake_install", False)),
        "property": kw["prop"],
        "notes": kw.get("notes", ""),
        "declared": {
            "build_succeeds": kw.get("build_ok", True),
            "product_exists": kw.get("product_exists", kw.get("build_ok", True)),
            "product_kind": kw.get("product_kind", "host-elf-exec"),
            "runpath": kw.get("runpath"),          # exact string, or None for absent
            "rpath_tag": kw.get("rpath_tag"),      # DT_RUNPATH / DT_RPATH / None
            "extra_products": list(kw.get("extra_products", [])),
            "leftovers_after_failed_build": list(kw.get("leftovers", [])),
            "starts_in_build_tree": kw.get("starts_in_build_tree",
                                           kw.get("build_ok", True)),
            "starts_after_build_tree_removed": kw.get("starts_relocated",
                                                      kw.get("build_ok", True)),
            "exit_code": kw.get("exit", 0),
            "expect": dict(kw.get("expect", {})),
            "build_duration_class": kw.get("build_duration", "seconds"),
            "product_min_bytes": kw.get("product_min_bytes"),
            "product_max_bytes": kw.get("product_max_bytes"),
            "toolchain_present": kw.get("toolchain_present", True),
            # ---- what the built FILE is, read out of it with readelf --------
            # Declared only where the recipe is about linkage; None means "this
            # recipe makes no claim", not "absent".
            "e_type": kw.get("e_type"),              # EXEC / DYN / REL
            "pie": kw.get("pie"),                    # bool
            "interpreter": kw.get("interpreter"),    # "present" / "absent"
            "needed_contains": list(kw.get("needed_contains", [])),
            "needed_empty": kw.get("needed_empty"),  # bool: DT_NEEDED list empty
            "has_symtab": kw.get("has_symtab"),      # bool
            "product_mode": kw.get("product_mode"),  # e.g. "0o644"
            # ---- what the BUILD said ----------------------------------------
            "build_stdout_contains": list(kw.get("build_stdout_contains", [])),
            "build_stderr_contains": list(kw.get("build_stderr_contains", [])),
            # ---- how the product BEHAVES -----------------------------------
            # A product killed by a signal has no exit code at all, so the two
            # are declared separately rather than folded into one number.
            "signal": kw.get("signal"),
            "run_stderr_contains": list(kw.get("run_stderr_contains", [])),
            # The relocated run gets its own declarations. Without these the
            # relocated check only asks whether main was reached, and a product
            # that starts and then cannot find its data would pass -- which is
            # exactly the shape the data_file family is about.
            "relocated_exit_code": kw.get("relocated_exit", kw.get("exit", 0)),
            "expect_relocated": dict(kw.get("expect_relocated", {})),
            "relocated_signal": kw.get("relocated_signal", kw.get("signal")),
            # ---- what an install promotes ----------------------------------
            "installed_present": list(kw.get("installed_present", [])),
            "installed_absent": list(kw.get("installed_absent", [])),
            # Stated when a declaration above is true only because of something
            # about THIS host, so nobody inherits the claim on another one. It is
            # not checked; it is a warning attached to the declaration it
            # qualifies. See portable-product-pe.
            "host_dependency": kw.get("host_dependency"),
        },
    }
    RECIPES.append(spec)
    return spec


COMMON_OK = {"PAYLOAD_KIND": "portable-source", "RESULT": "PASS"}

# ---- the ordinary shapes -------------------------------------------------
P("portable-c-single", "c_single", "bin/portable-c-single", "make",
  toolchain=["make", "cc"], prop="a single-file C program compiled at install",
  expect=dict(COMMON_OK, TRANSLATION_UNITS="1", BUILD_ISA="x86_64", ARGC="1",
              CHECKSUM_STABLE="yes", ISA_KNOWN="yes", ARGV0_PRESENT="yes"),
  notes="The control case. If this one is not clean, nothing else in the family "
        "tells you anything.")

P("portable-c-multi-tu", "c_multi", "bin/portable-c-multi-tu", "make",
  toolchain=["make", "cc"], prop="four translation units, compiled and linked",
  expect=dict(COMMON_OK, TRANSLATION_UNITS="4", ALL_UNITS_LINKED="yes",
              UTIL_MIX_STABLE="yes", CALC_SERIES_STABLE="yes", ISA_KNOWN="yes"),
  notes="A build with a dependency graph and an object list, not one compiler call.")

P("portable-cxx", "cxx", "bin/portable-cxx", "make",
  toolchain=["make", "c++"], prop="C++ compiled at install, with threads and exceptions",
  expect=dict(COMMON_OK, LANGUAGE="c++", CXX_STANDARD="201703",
              STATIC_INIT_ORDER="12", EXCEPTION_WHAT="deliberate",
              VECTOR_SUM="2080", THREADS_JOINED="4", THREAD_TOTAL="2999950",
              STATIC_INIT_BOTH_RAN="yes", EXCEPTION_CAUGHT="yes"),
  notes="VECTOR_SUM and THREAD_TOTAL are hand-computed: 1..64 sums to 2080, and "
        "the thread total is 10 * sum(k%7 for k<100000) = 10 * 299995.")

P("portable-cmake", "cmake_single", "bin/portable-cmake", "cmake",
  toolchain=["cmake", "cc"], prop="the second build driver: cmake rather than make",
  expect=dict(COMMON_OK, BUILD_SYSTEM="cmake",
              CMAKE_DEFINE_REACHED_COMPILER="yes", ISA_KNOWN="yes",
              ARGV0_PRESENT="yes"),
  notes="cmake decides the compiler by probing, wants its own build directory, "
        "and caches; the product still has to land where the manifest says.")

P("portable-command-driver", "command_script", "bin/portable-command-driver", "command",
  command=["sh", "build.sh"], toolchain=["sh", "cc"],
  prop="the third build driver: a declared argv, not a driver the runtime knows",
  expect=dict(COMMON_OK, BUILD_SYSTEM="command",
              BUILT_BY_MARKER="built-by-build-sh", MARKER_SET="yes"),
  notes="build.command is an argv and never a shell string, so there is no "
        "second quoting language between the manifest and exec.")

P("portable-shared-lib", "shared_lib", "bin/portable-shared-lib", "make",
  toolchain=["make", "cc"],
  prop="a build that produces a shared library and links the program against it",
  runpath="$ORIGIN/../lib", rpath_tag="DT_RUNPATH",
  extra_products=["lib/libutil.so"],
  expect=dict(COMMON_OK, UTIL_VALUE="4242", UTIL_BUILD_ID="libutil-1",
              SHARED_LIB_RESOLVED="yes", ARGV0_PRESENT="yes"),
  notes="Two artifacts with an ordering between them, and a run-time lookup that "
        "has to survive the payload being installed somewhere else.")

# ---- the awkward shapes --------------------------------------------------
P("portable-toolchain-absent", "toolchain_absent",
  "bin/portable-toolchain-absent", "make",
  toolchain=["make", "lexe-nonexistent-cc"],
  prop="a recipe declaring a toolchain this host does not have",
  build_ok=False, product_exists=False, product_kind=None,
  starts_in_build_tree=False, starts_relocated=False,
  toolchain_present=False,
  notes="Not a broken package: a cross-compiler for an ISA the host has not "
        "installed is exactly this shape. The tool is probed on PATH and the "
        "absence recorded before anything is built.")

P("portable-build-fails-partway", "build_fails",
  "bin/portable-build-fails-partway", "make",
  toolchain=["make", "cc"],
  prop="a build that succeeds for two objects and then fails",
  build_ok=False, product_exists=False, product_kind=None,
  leftovers=["src/first.o", "src/second.o"],
  starts_in_build_tree=False, starts_relocated=False,
  notes="It fails on a missing header, which is what half of real build failures "
        "are, and it fails AFTER two objects already exist: a partial tree, no "
        "product, non-zero exit.")

P("portable-product-pe", "product_pe", "bin/portable-product-pe.exe", "make",
  toolchain=["make", "x86_64-w64-mingw32-gcc"], architectures=["x86_64"],
  prop="a build that succeeds and produces a PE32+, not a host-ISA ELF",
  product_kind="pe",
  starts_in_build_tree=True, starts_relocated=True, exit=0,
  # The trailing \\r in every value is not a typo and is not tolerated: it is
  # DECLARED. A console program built against the Windows C runtime translates
  # \\n to \\r\\n on a text-mode stream, so this product's oracle arrives
  # CRLF-terminated and every line differs from its Linux-built equivalent by one
  # byte. Stripping CR in the oracle parser would have hidden that for the whole
  # corpus; declaring it keeps it visible exactly where it happens.
  expect={"PAYLOAD_KIND": "portable-source\r", "PRODUCT_FORMAT": "pe32plus\r",
          "RESULT": "PASS\r"},
  host_dependency="binfmt_misc handler WSLInterop-late, which makes the kernel "
                  "run a PE through Windows. On a host without it, exec of this "
                  "product fails and the specimen does not start. The CRLF line "
                  "endings in the declared oracle values come from the same "
                  "path: they are the Windows C runtime's text-mode translation.",
  notes="Declared TWICE, because the first declaration was wrong twice and both "
        "corrections are findings rather than tidying. "
        "First: the entrypoint was declared as bin/portable-product-pe, matching "
        "the Makefile's own target, and the build produced "
        "bin/portable-product-pe.exe -- mingw-w64 gcc appends .exe to the output "
        "name even when -o gives an explicit name without a suffix. That shape is "
        "kept as portable-product-path-mismatch. "
        "Second: the product was declared NOT to start, on the reasoning that a "
        "PE is not something a Linux kernel can exec. On this host it starts, "
        "exits 0 and prints its oracle in about 0.9 s, because binfmt_misc has "
        "WSLInterop-late registered and hands the file to Windows. Proved to be "
        "the binfmt path rather than anything about the name by copying the same "
        "bytes to a file with no .exe suffix, which also ran. The environment "
        "does NOT cross that boundary: with FIXTURE_ID=probe set, the program "
        "reported its compiled-in default instead, so getenv returned NULL. "
        "Third: every oracle line arrives with a trailing CR. The Windows C "
        "runtime translates \\n to \\r\\n on a text-mode stream, so this "
        "product's output is byte-for-byte different from the identical source "
        "built by cc, one byte per line. The declaration says so rather than the "
        "parser quietly stripping it. "
        "The consequence is worth stating plainly and is not mine to judge: on "
        "this host a `portable` package can produce and launch a Windows binary "
        "without ever declaring applicationType 'windows'.")

# The same recipe, with the entrypoint declared the way the Makefile names its
# own target. This entry exists because the FIRST version of the PE entry above
# declared `bin/portable-product-pe`, matching the Makefile, and the build
# produced `bin/portable-product-pe.exe` instead: mingw-w64 gcc appends .exe to
# the output name even when -o gives an explicit name without a suffix. That was
# a baseline mismatch, and the honest response was to keep both shapes rather
# than quietly rename one -- a successful build that does not produce the
# declared entrypoint is a different property from a successful build whose
# product is foreign, and this one is the property nobody thinks to test.
P("portable-product-path-mismatch", "product_pe", "bin/portable-product-pe", "make",
  toolchain=["make", "x86_64-w64-mingw32-gcc"], architectures=["x86_64"],
  prop="a build that reports success and does not produce the declared entrypoint",
  product_exists=False, product_kind=None,
  starts_in_build_tree=False, starts_relocated=False,
  notes="Byte-identical payload to portable-product-pe; only lexe.json differs, "
        "which is exactly the isolation wanted. The build exits 0, the toolchain "
        "was present, no diagnostic was printed, and the file the manifest "
        "names is not there.")

P("portable-product-shared-object", "product_shared_object",
  "bin/portable-product-shared-object", "make", toolchain=["make", "cc"],
  prop="a build that succeeds and produces a shared object where the entrypoint goes",
  product_kind="elf-shared-object",
  starts_in_build_tree=False, starts_relocated=False,
  notes="-shared where an executable was meant. Correct ELF, correct machine, no "
        "program interpreter: the gap between 'the build succeeded' and 'the "
        "product can be launched'.")

P("portable-slow-build", "slow_build", "bin/portable-slow-build", "make",
  toolchain=["make", "sh", "cc"],
  prop="a build slow enough to observe (generated sources, then a real compile)",
  build_duration="tens-of-seconds",
  expect=dict(COMMON_OK, GENERATED_UNITS="800", GEN_ALL_STABLE="yes"),
  notes="The time goes into the compiler rather than a sleep, because a sleep "
        "exercises none of what a build costs.")

P("portable-large-product", "large_product", "bin/portable-large-product", "make",
  toolchain=["make", "cc"], architectures=["x86_64", "aarch64"],
  prop="a small package whose built product is large",
  product_min_bytes=96 * 1024 * 1024,
  expect=dict(COMMON_OK, BLOB_BYTES="100663296", BLOB_FIRST="yes", BLOB_LAST="yes"),
  notes="A few kilobytes of source, 96 MiB of product. Any size taken from the "
        "package is wrong by four orders of magnitude.")

# ---- the rpath family ----------------------------------------------------
# One program, one library, six link lines. The declared RUNPATH below is a
# PREDICTION about what each idiom produces, written before the build ran.

RPATH_NOTE = ("Same sources and the same library as every other rpath variant; "
              "only the -Wl,-rpath argument differs.")

P("portable-rpath-make-var-pwd", "rpath_variants",
  "bin/portable-rpath-make-var-pwd", "make", toolchain=["make", "cc"],
  makefile_variant="make-var-pwd",
  prop="-Wl,-rpath,$(pwd)/../lib in a Makefile",
  runpath="/../lib", rpath_tag="DT_RUNPATH", extra_products=["lib/libutil.so"],
  starts_in_build_tree=False, starts_relocated=False,
  expect={},
  notes=RPATH_NOTE + " $(pwd) is a reference to a make VARIABLE named pwd, which "
        "nobody defined, so it expands to nothing and the rpath loses its front "
        "half. Predicted to fail even in the tree that built it.")

P("portable-rpath-shell-pwd", "rpath_variants",
  "bin/portable-rpath-shell-pwd", "make", toolchain=["make", "cc"],
  makefile_variant="shell-pwd",
  prop="-Wl,-rpath,$$PWD/../lib in a Makefile",
  runpath="{SRCDIR}/../lib", rpath_tag="DT_RUNPATH",
  extra_products=["lib/libutil.so"],
  starts_in_build_tree=True, starts_relocated=False,
  expect=dict(COMMON_OK, UTIL_VALUE="4242", SHARED_LIB_RESOLVED="yes"),
  notes=RPATH_NOTE + " PWD as the recipe shell sees it: an absolute path into "
        "the tree the build happened in.")

P("portable-rpath-curdir", "rpath_variants",
  "bin/portable-rpath-curdir", "make", toolchain=["make", "cc"],
  makefile_variant="curdir",
  prop="-Wl,-rpath,$(CURDIR)/../lib in a Makefile",
  runpath="{SRCDIR}/../lib", rpath_tag="DT_RUNPATH",
  extra_products=["lib/libutil.so"],
  starts_in_build_tree=True, starts_relocated=False,
  expect=dict(COMMON_OK, UTIL_VALUE="4242", SHARED_LIB_RESOLVED="yes"),
  notes=RPATH_NOTE + " CURDIR is make's own absolute working directory: the "
        "correct answer to 'where am I' and the wrong thing to bake into a "
        "product that outlives the directory.")

P("portable-rpath-shell-func-pwd", "rpath_variants",
  "bin/portable-rpath-shell-func-pwd", "make", toolchain=["make", "cc"],
  makefile_variant="shell-func-pwd",
  prop="-Wl,-rpath,$(shell pwd)/../lib in a Makefile",
  runpath="{SRCDIR}/../lib", rpath_tag="DT_RUNPATH",
  extra_products=["lib/libutil.so"],
  starts_in_build_tree=True, starts_relocated=False,
  expect=dict(COMMON_OK, UTIL_VALUE="4242", SHARED_LIB_RESOLVED="yes"),
  notes=RPATH_NOTE + " What people mean when they write $(pwd): correct as an "
        "expression, and still an absolute path into the build tree.")

P("portable-rpath-absolute", "rpath_variants",
  "bin/portable-rpath-absolute", "make", toolchain=["make", "cc"],
  makefile_variant="absolute",
  prop="-Wl,-rpath,/opt/lexe-workload/lib in a Makefile",
  runpath="/opt/lexe-workload/lib", rpath_tag="DT_RUNPATH",
  extra_products=["lib/libutil.so"],
  starts_in_build_tree=False, starts_relocated=False,
  expect={},
  notes=RPATH_NOTE + " The honest version of the same mistake, and by far the "
        "most common in locally built software. That directory does not exist "
        "on this host.")

P("portable-rpath-origin", "rpath_variants",
  "bin/portable-rpath-origin", "make", toolchain=["make", "cc"],
  makefile_variant="origin",
  prop="-Wl,-rpath,'$$ORIGIN/../lib' in a Makefile",
  runpath="$ORIGIN/../lib", rpath_tag="DT_RUNPATH",
  extra_products=["lib/libutil.so"],
  starts_in_build_tree=True, starts_relocated=True,
  expect=dict(COMMON_OK, UTIL_VALUE="4242", SHARED_LIB_RESOLVED="yes"),
  notes=RPATH_NOTE + " The relocatable idiom, and the only one of the six "
        "predicted to still start once the build tree is gone.")

P("portable-rpath-origin-dtrpath", "rpath_variants",
  "bin/portable-rpath-origin-dtrpath", "make", toolchain=["make", "cc"],
  makefile_variant="origin-dtrpath",
  prop="the relocatable string recorded under DT_RPATH instead of DT_RUNPATH",
  runpath="$ORIGIN/../lib", rpath_tag="DT_RPATH",
  extra_products=["lib/libutil.so"],
  starts_in_build_tree=True, starts_relocated=True,
  expect=dict(COMMON_OK, UTIL_VALUE="4242", SHARED_LIB_RESOLVED="yes"),
  notes=RPATH_NOTE + " -Wl,--disable-new-dtags. The string is identical to the "
        "origin variant and the TAG is different, which changes the search "
        "order: DT_RPATH is consulted before LD_LIBRARY_PATH and cannot be "
        "overridden by it, DT_RUNPATH after and can. Anything that reads only "
        "the RUNPATH field concludes this product has no search path at all.")

P("portable-rpath-none", "rpath_variants", "bin/portable-rpath-none", "make",
  toolchain=["make", "cc"], makefile_variant="none",
  prop="a program linked against a payload library with no run-time search path",
  runpath=None, rpath_tag=None, extra_products=["lib/libutil.so"],
  starts_in_build_tree=False, starts_relocated=False, expect={},
  notes=RPATH_NOTE + " The control for the whole family: -L is a LINK-time path "
        "and says nothing about run time, so the link succeeds without a "
        "diagnostic and the product cannot start anywhere, including the "
        "directory that built it.")

P("portable-rpath-origin-double-quoted", "rpath_variants",
  "bin/portable-rpath-origin-double-quoted", "make", toolchain=["make", "cc"],
  makefile_variant="origin-double-quoted",
  prop='-Wl,-rpath,"$$ORIGIN/../lib" in a Makefile (double quotes)',
  runpath="/../lib", rpath_tag="DT_RUNPATH", extra_products=["lib/libutil.so"],
  starts_in_build_tree=False, starts_relocated=False, expect={},
  notes=RPATH_NOTE + " The $$ gets one dollar past make correctly and then the "
        "double quotes let the SHELL expand $ORIGIN, an ordinary environment "
        "variable nobody has set, to nothing. Same wreckage as the $(pwd) "
        "variant from the opposite direction: there make ate it, here the "
        "shell did.")

P("portable-rpath-origin-single-dollar", "rpath_variants",
  "bin/portable-rpath-origin-single-dollar", "make", toolchain=["make", "cc"],
  makefile_variant="origin-single-dollar",
  prop="-Wl,-rpath,'$ORIGIN/../lib' in a Makefile (one dollar, not two)",
  runpath="RIGIN/../lib", rpath_tag="DT_RUNPATH",
  extra_products=["lib/libutil.so"],
  starts_in_build_tree=False, starts_relocated=False, expect={},
  notes=RPATH_NOTE + " make reads $O as a reference to a variable named O, "
        "which nobody defined, leaving the literal RIGIN/../lib. A RELATIVE "
        "DT_RUNPATH is legal -- it is resolved against the process working "
        "directory -- so the linker accepts it silently and the product carries "
        "a search path that depends on where it is launched from.")


# ---- the language standards ----------------------------------------------
# One source per language, several -std flags. What the specimen reports is what
# the COMPILER says it was given, never what the recipe claims it asked for.

STD_C_OK = dict(COMMON_OK, LANGUAGE="c", STDC_HOSTED="1",
                CHECKSUM_STABLE="yes", ISA_KNOWN="yes")
STD_C_NOTE = ("One source, five -std flags. The file is strict C89 so it "
              "compiles unchanged under all five with -pedantic-errors, which "
              "is what makes the comparison a comparison.")

P("portable-std-c89", "std_c", "bin/portable-std-c89", "make",
  toolchain=["make", "cc"], makefile_variant="c89",
  prop="C89 requested with -std=c89 -pedantic-errors",
  expect=dict(STD_C_OK, STDC_VERSION="undefined", STRICT_ANSI="yes"),
  notes=STD_C_NOTE + " __STDC_VERSION__ does not exist in C89 at all, so the "
        "specimen reports it as undefined rather than inventing a 0.")

P("portable-std-c99", "std_c", "bin/portable-std-c99", "make",
  toolchain=["make", "cc"], makefile_variant="c99",
  prop="C99 requested with -std=c99 -pedantic-errors",
  expect=dict(STD_C_OK, STDC_VERSION="199901", STRICT_ANSI="yes"),
  notes=STD_C_NOTE)

P("portable-std-c11", "std_c", "bin/portable-std-c11", "make",
  toolchain=["make", "cc"], makefile_variant="c11",
  prop="C11 requested with -std=c11 -pedantic-errors",
  expect=dict(STD_C_OK, STDC_VERSION="201112", STRICT_ANSI="yes"),
  notes=STD_C_NOTE)

P("portable-std-c17", "std_c", "bin/portable-std-c17", "make",
  toolchain=["make", "cc"], makefile_variant="c17",
  prop="C17 requested with -std=c17 -pedantic-errors",
  expect=dict(STD_C_OK, STDC_VERSION="201710", STRICT_ANSI="yes"),
  notes=STD_C_NOTE)

P("portable-std-gnu89", "std_c", "bin/portable-std-gnu89", "make",
  toolchain=["make", "cc"], makefile_variant="gnu89",
  prop="C89 plus GNU extensions, requested with -std=gnu89",
  expect=dict(STD_C_OK, STDC_VERSION="undefined", STRICT_ANSI="no"),
  notes=STD_C_NOTE + " The pair with portable-std-c89 is the point: the "
        "language version is identical and __STRICT_ANSI__ is not, so the two "
        "products differ in what the compiler would have ACCEPTED rather than "
        "in what this source used.")

STD_CXX_OK = dict(COMMON_OK, LANGUAGE="c++", VECTOR_SUM="2080",
                  STRING_CONCAT="portable-source", EXCEPTION_CAUGHT="yes")
STD_CXX_NOTE = ("One source, four -std flags. Written to C++11 so nothing in it "
                "was added or removed by a later standard; VECTOR_SUM is "
                "hand-computed (1..64 sums to 2080) rather than checked against "
                "a second copy of the same loop.")

P("portable-std-cxx11", "std_cxx", "bin/portable-std-cxx11", "make",
  toolchain=["make", "c++"], makefile_variant="cxx11",
  prop="C++11 requested with -std=c++11",
  expect=dict(STD_CXX_OK, CPLUSPLUS="201103"), notes=STD_CXX_NOTE)

P("portable-std-cxx14", "std_cxx", "bin/portable-std-cxx14", "make",
  toolchain=["make", "c++"], makefile_variant="cxx14",
  prop="C++14 requested with -std=c++14",
  expect=dict(STD_CXX_OK, CPLUSPLUS="201402"), notes=STD_CXX_NOTE)

P("portable-std-cxx17", "std_cxx", "bin/portable-std-cxx17", "make",
  toolchain=["make", "c++"], makefile_variant="cxx17",
  prop="C++17 requested with -std=c++17",
  expect=dict(STD_CXX_OK, CPLUSPLUS="201703"), notes=STD_CXX_NOTE)

P("portable-std-cxx20", "std_cxx", "bin/portable-std-cxx20", "make",
  toolchain=["make", "c++"], makefile_variant="cxx20",
  prop="C++20 requested with -std=c++20",
  expect=dict(STD_CXX_OK, CPLUSPLUS="202002"), notes=STD_CXX_NOTE)

# ---- linkage: six link lines, six different FILES -------------------------
# Every declaration below is about the built file rather than the program, and
# is read out of it with readelf. The program's own opinion of its linkage would
# be a compile-time guess.

LINK_OK = dict(COMMON_OK, CHECKSUM_STABLE="yes", ISA_KNOWN="yes")

P("portable-link-pie", "linkage", "bin/portable-link-pie", "make",
  toolchain=["make", "cc"], makefile_variant="pie",
  prop="the toolchain default: a position-independent executable",
  e_type="DYN", pie=True, interpreter="present",
  needed_contains=["libc.so.6"], has_symtab=True,
  expect=LINK_OK,
  notes="e_type DYN, which is the SAME e_type a shared library has. Telling a "
        "PIE from a library needs the program headers, not the ELF type.")

P("portable-link-no-pie", "linkage", "bin/portable-link-no-pie", "make",
  toolchain=["make", "cc"], makefile_variant="no-pie",
  prop="-no-pie: a fixed-address executable, still dynamically linked",
  e_type="EXEC", pie=False, interpreter="present",
  needed_contains=["libc.so.6"], has_symtab=True,
  expect=LINK_OK,
  notes="The pre-PIE shape, and still what a great deal of locally built "
        "software produces.")

P("portable-link-static", "linkage", "bin/portable-link-static", "make",
  toolchain=["make", "cc"], makefile_variant="static",
  prop="-static: no program interpreter and an empty DT_NEEDED",
  e_type="EXEC", pie=False, interpreter="absent",
  needed_empty=True, has_symtab=True,
  expect=LINK_OK,
  notes="Nothing for the loader to fail to find, so nothing that relocation "
        "can break. The opposite end of the same axis as the rpath family: "
        "where that family asks how a product finds its libraries, this one "
        "has none to find.")

P("portable-link-static-pie", "linkage", "bin/portable-link-static-pie", "make",
  toolchain=["make", "cc"], makefile_variant="static-pie",
  prop="-static-pie: e_type DYN with no interpreter and an empty DT_NEEDED",
  e_type="DYN", pie=True, interpreter="absent",
  needed_empty=True, has_symtab=True,
  expect=LINK_OK,
  notes="Sounds contradictory and is not. The specimen exists because code "
        "that infers 'dynamically linked' from e_type DYN, or 'has an "
        "interpreter' from PIE, is wrong exactly here and nowhere else in the "
        "corpus.")

P("portable-link-stripped", "linkage", "bin/portable-link-stripped", "make",
  toolchain=["make", "cc"], makefile_variant="stripped",
  prop="-s: the same program with no symbol table in the file",
  e_type="DYN", pie=True, interpreter="present",
  needed_contains=["libc.so.6"], has_symtab=False,
  expect=LINK_OK,
  notes="Nothing about the run changes. What changes is whether .symtab is "
        "there, which is the one difference between this specimen and "
        "portable-link-pie.")

P("portable-link-debug", "linkage", "bin/portable-link-debug", "make",
  toolchain=["make", "cc"], makefile_variant="debug",
  prop="-g: debug information in the product",
  e_type="DYN", pie=True, interpreter="present",
  needed_contains=["libc.so.6"], has_symtab=True,
  expect=LINK_OK,
  notes="The ordinary state of a locally built binary, and several times the "
        "size of the stripped one from identical source.")

# ---- runtime behaviour: one product, many manifests -----------------------
# These specimens vary `entrypoint.arguments` and nothing else. It is the only
# part of the manifest no other recipe in the corpus exercises, and it buys the
# runtime behaviours a launcher has to survive without a source tree each.

RUN_NOTE = ("Same payload, same build, same product bytes as every other "
            "portable-run-* specimen. Only entrypoint.arguments differs.")
RUN_OK = dict(COMMON_OK, MODE_KNOWN="yes")


def RUN(rid, args, prop, notes="", **kw):
    expect = dict(RUN_OK, ARGC=str(1 + len(args)))
    if args:
        expect["MODE"] = args[0]
    else:
        expect["MODE"] = "report"
    for i, a in enumerate(args, 1):
        expect["ARGV_%d" % i] = a
    expect.update(kw.pop("extra_expect", {}))
    # RESULT stays PASS even for the specimens that exit 7 or die on SIGSEGV:
    # the program did exactly what it was told, and the unusual exit status is a
    # separate declaration. Conflating the two is how a launcher ends up
    # reporting a deliberate exit code as a broken payload.
    return P(rid, "run_modes", "bin/portable-run", "make",
             toolchain=["make", "cc"], arguments=args, prop=prop,
             expect=expect, expect_relocated=dict(expect),
             notes=RUN_NOTE + (" " + notes if notes else ""), **kw)


RUN("portable-run-no-args", [],
    "a product launched with no arguments at all",
    "argc is 1 and argv[0] is the only thing there, which is the baseline every "
    "other member of this family is measured against.")

RUN("portable-run-args-three", ["args", "alpha", "beta"],
    "three fixed arguments delivered from the manifest to argv")

RUN("portable-run-arg-with-space", ["args", "one two three"],
    "an argument containing spaces, delivered as ONE argv element",
    "The manifest carries an argv list rather than a command string, so there "
    "is no quoting language between the manifest and exec and this is one "
    "argument rather than three. A fixture that went through a shell would "
    "report ARGC=5 here.")

RUN("portable-run-arg-empty", ["args", ""],
    "an empty-string argument",
    "The schema notes explicitly that entrypoint.arguments accepts an empty "
    "string where build.command does not. This is the specimen that shows an "
    "empty argument survives all the way to argv rather than being dropped.")

RUN("portable-run-arg-unicode", ["args", "αβγ ünïcode"],
    "an argument containing non-ASCII characters",
    "The manifest is JSON, so this travels as \\u escapes and has to arrive at "
    "argv as UTF-8 bytes.")

RUN("portable-run-many-args", ["args"] + ["a%d" % i for i in range(40)],
    "forty-one fixed arguments")

RUN("portable-run-exit-7", ["exit", "7"],
    "a product that exits with an unusual non-zero status",
    "Exit 7 is a RESULT the program chose, not a failure: the oracle still "
    "says PASS. Anything that equates a non-zero exit with a broken specimen "
    "gets this one wrong.",
    exit=7, extra_expect={"EXIT_REQUESTED": "7"})

RUN("portable-run-exit-255", ["exit", "255"],
    "a product that exits with the largest status a wait() can carry",
    exit=255, extra_expect={"EXIT_REQUESTED": "255"})

RUN("portable-run-crash-segv", ["crash"],
    "a product that starts, prints its oracle and then dies on SIGSEGV",
    "There is no exit code at all, which is why the declaration carries a "
    "signal instead of one. The program flushes stdout before dereferencing "
    "null on purpose: without that the pipe is still block-buffered and the "
    "specimen would be indistinguishable from one that never reached main.",
    exit=None, signal=11, extra_expect={"FATAL_KIND": "segv"})

RUN("portable-run-abort", ["abort"],
    "a product that starts and then raises SIGABRT",
    "The other fatal signal a program gives itself, and a different number.",
    exit=None, signal=6, extra_expect={"FATAL_KIND": "abort"})

RUN("portable-run-stderr", ["stderr"],
    "a product that writes to stderr as well as stdout",
    "Two streams, and the oracle is only on one of them.",
    run_stderr_contains=["PORTABLE_RUN_STDERR_MARKER"],
    extra_expect={"STDERR_WRITTEN": "yes"})

RUN("portable-run-env-present", ["env", "FIXTURE_ID"],
    "a product that reads an environment variable that IS set",
    "FIXTURE_ID is set by the harness for every run in this corpus, so this "
    "specimen is the positive control for the pair.",
    extra_expect={"ENV_NAME": "FIXTURE_ID", "ENV_PRESENT": "yes"})

RUN("portable-run-env-absent", ["env", "LEXE_VARIABLE_THAT_IS_NOT_SET"],
    "a product that reads an environment variable that is NOT set",
    "The build and run environments here are deliberately tiny, so this is a "
    "real absence rather than a name nobody happened to use.",
    extra_expect={"ENV_NAME": "LEXE_VARIABLE_THAT_IS_NOT_SET",
                  "ENV_PRESENT": "no"})

RUN("portable-run-write-file", ["write", "written-by-the-product.txt"],
    "a product that writes a file into its working directory and reads it back",
    "The path is relative, so the file lands in whatever working directory the "
    "launcher chose -- which is a different directory for the build-tree run "
    "and the relocated run, and both are declared to succeed.",
    extra_expect={"WRITE_PATH": "written-by-the-product.txt",
                  "WRITE_ROUNDTRIP": "yes"})

RUN("portable-run-spin-short", ["spin", "1000"],
    "a product that finishes immediately",
    extra_expect={"SPIN_ROUNDS": "1000", "SPIN_NONZERO": "yes"})

RUN("portable-run-spin-long", ["spin", "1200000000"],
    "a product that runs for seconds rather than milliseconds",
    "The work is integer arithmetic, so SPIN_VALUE is identical on every "
    "machine and only the WALL TIME differs. No duration is declared: a "
    "declared duration would be a performance assertion, and this corpus does "
    "not make those -- the time each run took is in runs.*.duration_ms as an "
    "observation, beside the load average the whole generation ran under.",
    extra_expect={"SPIN_ROUNDS": "1200000000", "SPIN_NONZERO": "yes"})

RUN("portable-run-stdin-eof", ["stdin"],
    "a product that reads stdin and finds it already at end of file",
    "Every run in this corpus is given an empty stdin rather than an inherited "
    "terminal, so a product that blocks on input would hang instead of "
    "reporting. This specimen proves it does not.",
    extra_expect={"STDIN_SAW_BYTES": "no", "STDIN_AT_EOF": "yes"})

# ---- a product that needs a FILE at run time ------------------------------
# The rpath question asked about data instead of libraries, with the same three
# answers and one important difference: there is no loader, so a wrong answer
# produces no diagnostic at all unless the program checks.

DATA_OK = dict(COMMON_OK, PATH_RESOLVED="yes", DATA_FOUND="yes",
               DATA_TOKEN="portable-data-file-token-1", DATA_TOKEN_OK="yes")

P("portable-data-proc-self-exe", "data_file", "bin/portable-data-proc-self-exe",
  "make", toolchain=["make", "cc"], makefile_variant="proc-self-exe",
  prop="a product that finds its data file relative to /proc/self/exe",
  extra_products=["share/message.txt"],
  installed_present=["share/message.txt"],
  expect=dict(DATA_OK, LOOKUP="proc-self-exe"),
  expect_relocated=dict(DATA_OK, LOOKUP="proc-self-exe"),
  notes="The relocatable answer, and the only one of the three that still "
        "works once the build tree is gone. The data file is installed into "
        "payload/share rather than read out of payload/src, because src is "
        "exactly what an install leaves behind.")

P("portable-data-baked-abs-path", "data_file", "bin/portable-data-baked-abs-path",
  "make", toolchain=["make", "cc"], makefile_variant="baked-abs-path",
  prop="a product with the build directory compiled into it as a string constant",
  extra_products=["share/message.txt"],
  installed_present=["share/message.txt"],
  expect=dict(DATA_OK, LOOKUP="baked-abs-path",
              BAKED_DATA_DIR="{SRCDIR}/../share"),
  relocated_exit=3,
  expect_relocated={"PAYLOAD_KIND": "portable-source", "RESULT": "FAIL",
                    "LOOKUP": "baked-abs-path",
                    "BAKED_DATA_DIR": "{SRCDIR}/../share",
                    "PATH_RESOLVED": "yes", "DATA_FOUND": "no",
                    "DATA_TOKEN": "<none>", "DATA_TOKEN_OK": "no"},
  notes="-DDATA_DIR='\"$(CURDIR)/../share\"'. The same mistake as an absolute "
        "rpath, one layer up and quieter: no loader is involved, so there is no "
        "loader message, no exit 127 and no ldd line -- just a file that is not "
        "there, which only this program's own check reports. The declared "
        "BAKED_DATA_DIR is the build directory itself, which is why it is "
        "written with {SRCDIR}: the value is not knowable until the build has "
        "a directory, and it is a DECLARED value rather than an observation "
        "because a build path becoming a constant in the product is the whole "
        "property.")

P("portable-data-cwd-relative", "data_file", "bin/portable-data-cwd-relative",
  "make", toolchain=["make", "cc"], makefile_variant="cwd-relative",
  prop="a product that looks for its data relative to the working directory",
  extra_products=["share/message.txt"],
  installed_present=["share/message.txt"],
  exit=3, relocated_exit=3,
  expect={"PAYLOAD_KIND": "portable-source", "RESULT": "FAIL",
          "LOOKUP": "cwd-relative", "PATH_RESOLVED": "yes",
          "DATA_FOUND": "no", "DATA_TOKEN": "<none>", "DATA_TOKEN_OK": "no"},
  expect_relocated={"PAYLOAD_KIND": "portable-source", "RESULT": "FAIL",
                    "LOOKUP": "cwd-relative", "PATH_RESOLVED": "yes",
                    "DATA_FOUND": "no", "DATA_TOKEN": "<none>",
                    "DATA_TOKEN_OK": "no"},
  notes="Declared to fail in BOTH runs, including the one in the tree that "
        "built it. That is not a broken recipe: a launcher chooses the working "
        "directory and it is never the payload root, so this shape is broken "
        "everywhere and looks fine to anyone who tests it by cd-ing into the "
        "payload first.")

# ---- what a build can DO --------------------------------------------------

P("portable-outcome-warns", "outcomes", "bin/portable-outcome-warns", "make",
  toolchain=["make", "cc"], makefile_variant="warns",
  prop="a build that emits warnings, exits 0, and produces a working product",
  build_stderr_contains=["warning:"],
  expect=dict(COMMON_OK, WARNED_BUT_BUILT="yes", SIGN_COMPARE_EQUAL="yes",
              HELPER="1"),
  notes="The most common state of real source. Anything that treats a "
        "non-empty build stderr as failure rejects most of the software in the "
        "world, so the declaration asserts BOTH that the build succeeded and "
        "that it complained.")

P("portable-outcome-link-fails", "outcomes", "bin/portable-outcome-link-fails",
  "make", toolchain=["make", "cc"], makefile_variant="link-fails",
  prop="a build that compiles cleanly and fails at the LINK step",
  build_ok=False, product_exists=False, product_kind=None,
  starts_in_build_tree=False, starts_relocated=False,
  leftovers=["src/undef_ref.o"],
  build_stderr_contains=["undefined reference"],
  notes="A different shape from a compile failure: every translation unit was "
        "accepted, the object file exists, and the diagnostic names a SYMBOL "
        "rather than a file and a line. A consumer scraping for 'error:' finds "
        "nothing -- GNU ld says 'undefined reference to'.")

P("portable-outcome-missing-sys-header", "outcomes",
  "bin/portable-outcome-missing-sys-header", "make",
  toolchain=["make", "cc"], makefile_variant="missing-sys-header",
  prop="a build needing a system header that is not installed on this host",
  build_ok=False, product_exists=False, product_kind=None,
  starts_in_build_tree=False, starts_relocated=False,
  build_stderr_contains=["gtk/gtk.h"],
  notes="Every declared TOOL is present and the build still cannot proceed. "
        "This is what a package with a -dev dependency looks like on a machine "
        "that has not got it, and it is a different failure from "
        "portable-toolchain-absent, which can be detected before the user is "
        "asked to approve anything.")

P("portable-outcome-no-rule", "outcomes", "bin/portable-outcome-no-rule", "make",
  toolchain=["make", "cc"], makefile_variant="no-rule",
  prop="a build that fails before invoking the compiler at all",
  build_ok=False, product_exists=False, product_kind=None,
  starts_in_build_tree=False, starts_relocated=False,
  build_stderr_contains=["No rule to make target"],
  notes="make is asked for a prerequisite that is neither a file nor a rule. "
        "Nothing is compiled, no object exists, and the diagnostic comes from "
        "make rather than from cc -- so a consumer that looks for compiler "
        "output to explain a failure finds none at all.")

P("portable-outcome-no-product", "outcomes", "bin/portable-outcome-no-product",
  "make", toolchain=["make", "cc"], makefile_variant="no-product",
  prop="a build that exits 0 and puts the product at a different path",
  product_exists=False, product_kind=None,
  starts_in_build_tree=False, starts_relocated=False,
  extra_products=["bin/portable-outcome-somewhere-else"],
  notes="The same property as portable-product-path-mismatch without needing a "
        "cross-compiler to produce it: exit 0, no diagnostic, and a perfectly "
        "good binary sitting next to the declared path.")

P("portable-outcome-swallowed-error", "outcomes",
  "bin/portable-outcome-swallowed-error", "make",
  toolchain=["make", "cc"], makefile_variant="swallowed-error",
  prop="a build that exits 0 because the recipe told make to ignore a failure",
  product_exists=False, product_kind=None,
  starts_in_build_tree=False, starts_relocated=False,
  build_stdout_contains=["build finished"],
  build_stderr_contains=["(ignored)"],
  notes="A leading `-` on the recipe line. make reports 'Error 1 (ignored)' and "
        "carries on, so the build exits 0 with a real compiler error in its "
        "stderr and nothing at the entrypoint. Anything that trusts the exit "
        "status alone records this as a successful build.")

P("portable-outcome-empty-product", "outcomes",
  "bin/portable-outcome-empty-product", "make",
  toolchain=["make", "cc"], makefile_variant="empty-product",
  prop="a build that creates the declared entrypoint as a zero-byte file",
  product_kind="other", product_max_bytes=0, product_mode="0o755",
  starts_in_build_tree=False, starts_relocated=False,
  notes="The path exists, the mode is right, and there is nothing to execute: "
        "file(1) says 'empty' and execve fails with ENOEXEC. A check that stats "
        "the entrypoint and stops there passes this specimen.")

P("portable-outcome-not-executable", "outcomes",
  "bin/portable-outcome-not-executable", "make",
  toolchain=["make", "cc"], makefile_variant="not-executable",
  prop="a correct ELF executable left mode 0644",
  product_mode="0o644", e_type="DYN",
  starts_in_build_tree=False, starts_relocated=False,
  notes="Every ELF fact about the file is right and it cannot be launched. The "
        "failure is a PermissionError from execve rather than a loader message "
        "or a non-zero exit, so it happens before the program exists. Measured "
        "on ext4 under the build root: mode is meaningless on DrvFS, which is "
        "why nothing in this corpus builds under /mnt/c.")

P("portable-outcome-object", "outcomes", "bin/portable-outcome-object.o", "make",
  toolchain=["make", "cc"], makefile_variant="object",
  prop="a build that stops at -c, leaving a relocatable object at the entrypoint",
  product_kind="elf-object", e_type="REL", product_mode="0o755",
  starts_in_build_tree=False, starts_relocated=False,
  notes="A valid ELF of the right machine with no entry point and no program "
        "headers: one step earlier than the shared-object specimen on the same "
        "axis of 'the build succeeded' versus 'the product can be launched'.")

P("portable-outcome-archive", "outcomes",
  "bin/libportable-outcome-archive.a", "make",
  toolchain=["make", "cc", "ar"], makefile_variant="archive",
  prop="a static archive at the entrypoint, about which file(1) and readelf disagree",
  product_kind="elf-other", e_type="REL", product_mode="0o755",
  starts_in_build_tree=False, starts_relocated=False,
  notes="The most interesting classifier case in the corpus. file(1) says "
        "'current ar archive'; readelf -h SUCCEEDS and reports REL, having "
        "read the first member rather than the file. The generator's classifier "
        "consults both and lands on 'elf-other' -- a category it reaches for no "
        "other specimen -- which is the honest answer for a file that is an "
        "archive of ELFs and not an ELF.")

P("portable-outcome-text-product", "outcomes",
  "bin/portable-outcome-text-product", "make",
  toolchain=["make", "cc"], makefile_variant="text-product",
  prop="a text file with the executable bit set and no shebang",
  product_kind="script", product_mode="0o755",
  starts_in_build_tree=False, starts_relocated=False,
  notes="A shell would run this by falling back to itself; execve will not, and "
        "fails with ENOEXEC. 'Executable bit set' and 'executable' are "
        "different claims, and this is the specimen where they come apart.")

P("portable-outcome-script-wrapper", "outcomes",
  "bin/portable-outcome-script.sh", "make",
  toolchain=["make", "cc"], makefile_variant="script-wrapper",
  prop="an entrypoint that is a shell script wrapping a compiled binary",
  product_kind="script", product_mode="0o755",
  extra_products=["bin/portable-outcome-wrapped"],
  expect=dict(COMMON_OK, WRAPPER="sh", ISA_KNOWN="yes"),
  expect_relocated=dict(COMMON_OK, WRAPPER="sh", ISA_KNOWN="yes"),
  notes="Extremely common -- it is how a program that needs an environment "
        "variable, a working directory or a library path gets one -- and it "
        "means the declared entrypoint is not an ELF at all. The wrapper finds "
        "its binary from $0, so it survives relocation; a wrapper with an "
        "absolute path in it would be the rpath mistake in shell.")

# ---- several products from one package ------------------------------------

P("portable-multi-exec-first", "multi_exec", "bin/portable-multi-alpha", "make",
  toolchain=["make", "cc"],
  prop="three executables from one build, the first declared as the entrypoint",
  extra_products=["bin/portable-multi-beta", "bin/portable-multi-gamma"],
  expect=dict(COMMON_OK, PROGRAM="alpha", PROGRAMS_IN_PACKAGE="3"),
  notes="A package is not required to produce exactly one program, and a "
        "manifest names exactly one entrypoint -- so two of the three products "
        "are files an install has to carry that nothing will ever launch "
        "through the manifest.")

P("portable-multi-exec-last", "multi_exec", "bin/portable-multi-gamma", "make",
  toolchain=["make", "cc"],
  prop="the same three executables with the LAST one declared as the entrypoint",
  extra_products=["bin/portable-multi-alpha", "bin/portable-multi-beta"],
  expect=dict(COMMON_OK, PROGRAM="gamma", PROGRAMS_IN_PACKAGE="3"),
  notes="Byte-identical payload to portable-multi-exec-first; only lexe.json "
        "differs. Anything that assumes the entrypoint is whatever the build "
        "produced first, or alphabetically, gets this one wrong.")

# ---- libraries that are not shared ----------------------------------------

P("portable-static-lib", "static_lib", "bin/portable-static-lib", "make",
  toolchain=["make", "cc", "ar"],
  prop="a static library and its consumer, produced by one build",
  extra_products=["lib/libutil.a"],
  needed_contains=["libc.so.6"], runpath=None, rpath_tag=None,
  expect=dict(COMMON_OK, LINK_KIND="static-archive", UTIL_VALUE="4242",
              UTIL_BUILD_ID="libutil-static-1", ARCHIVE_LINKED="yes"),
  expect_relocated=dict(COMMON_OK, LINK_KIND="static-archive",
                        UTIL_VALUE="4242", UTIL_BUILD_ID="libutil-static-1",
                        ARCHIVE_LINKED="yes"),
  notes="The counterpart to portable-shared-lib. The archive is still installed "
        "as a product, and none of it is needed at run time: there is no "
        "DT_NEEDED entry for it and no search path to get wrong, so relocation "
        "cannot break this shape. `ar` is a declared tool of its own, because a "
        "host with cc and make and no binutils cannot run this recipe.")

P("portable-mixed-c-cxx", "mixed_c_cxx", "bin/portable-mixed-c-cxx", "make",
  toolchain=["make", "cc", "c++"],
  prop="one product from a C translation unit and a C++ translation unit",
  needed_contains=["libstdc++.so.6", "libc.so.6"],
  expect=dict(COMMON_OK, TRANSLATION_UNITS="2", MAIN_LANGUAGE="c++",
              CPART_LANGUAGE="c", CPART_VALUE="1701", CXX_STRING="mixed-ok",
              BOTH_UNITS_LINKED="yes"),
  notes="Two compilers in one build, and the LINK has to be driven by c++: a "
        "link driven by cc produces undefined references to the C++ runtime. "
        "The extern \"C\" guard in the shared header is the other half -- "
        "without it the C++ unit asks the linker for a mangled name nobody "
        "defined.")

P("portable-cxx-links-c-archive", "cxx_c_archive", "bin/portable-cxx-c-archive",
  "make", toolchain=["make", "cc", "c++", "ar"],
  prop="a C++ product linking a C static library the same build produced",
  extra_products=["lib/libclib.a"],
  needed_contains=["libstdc++.so.6"],
  expect=dict(COMMON_OK, MAIN_LANGUAGE="c++",
              DEPENDENCY_KIND="c-static-archive", CLIB_ANSWER="2718",
              CLIB_ID="clib-archive-1", VECTOR_TOTAL="10872",
              ARCHIVE_LINKED="yes"),
  notes="Four declared tools and an ordering: cc compiles, ar archives, c++ "
        "links. VECTOR_TOTAL is hand-computed as 4 * 2718 = 10872.")

# ---- build drivers and build shapes ---------------------------------------

P("portable-make-recursive", "make_recursive", "bin/portable-make-recursive",
  "make", toolchain=["make", "cc"],
  prop="a recursive make: two sub-makes in subdirectories, then a link",
  expect=dict(COMMON_OK, BUILD_SHAPE="recursive-make", SUBDIRS="2",
              CORE_ID="core-1", UTIL_ID="util-1", UTIL_ANSWER="31337",
              BOTH_SUBDIRS_LINKED="yes"),
  notes="Three makefiles, two of which know nothing about the one above them. "
        "$(MAKE) rather than `make` in the recipes, because $(MAKE) carries the "
        "jobserver and the command-line variables into the sub-make and a bare "
        "`make` loses both -- which shows up only under -j.")

PARALLEL_OK = dict(COMMON_OK, TRANSLATION_UNITS="5", PARTS_COMBINED="4",
                   COMBINED_NONZERO="yes")

P("portable-make-serial", "parallel", "bin/portable-parallel", "make",
  toolchain=["make", "cc"],
  prop="the control for the parallel pair: the same build with no -j at all",
  build_stdout_contains=["PORTABLE_PARALLEL_SEEN=no"],
  expect=PARALLEL_OK,
  notes="Byte-identical payload to the two parallel specimens and byte-identical "
        "in everything but MAKEFLAGS. It exists because the product is correct "
        "whether or not -j arrived, so without a specimen that declares -j did "
        "NOT arrive there is nothing the other two are being compared against.")

P("portable-make-parallel-env", "parallel", "bin/portable-parallel", "make",
  toolchain=["make", "cc"], build_env_extra={"MAKEFLAGS": "-j4"},
  prop="a make build run with four parallel jobs, requested through MAKEFLAGS",
  build_stdout_contains=["PORTABLE_PARALLEL_SEEN=yes"],
  expect=PARALLEL_OK,
  notes="The canonical `make -C src` invocation with MAKEFLAGS=-j4 in the "
        "environment, which is how a parallel build is requested without "
        "changing the command line. The four objects have no dependency on each "
        "other and the combining order in the program is fixed, so a rule that "
        "relied on make's serial ordering would produce a link error or a stale "
        "object here rather than a different answer. "
        "PORTABLE_PARALLEL_SEEN is declared because a correct product does not "
        "show that -j arrived: the first version of this recipe asserted only "
        "the product, and would have passed unchanged with the environment "
        "addition deleted. The Makefile now reports what make itself was given. "
        "That probe was wrong once and the correction is a finding rather than "
        "tidying: written as a parse-time `ifneq (,$(findstring j,$(MAKEFLAGS)))` "
        "it reported `no` for a build make had been given -j4, because GNU make "
        "appends -j and --jobserver-auth to MAKEFLAGS AFTER reading the "
        "makefiles -- at parse time the variable held only `w`, the "
        "--print-directory that -C implies. Expanded inside a recipe line the "
        "same variable reads `w -j4 --jobserver-auth=3,4`. Any makefile that "
        "changes its own behaviour from a parse-time look at MAKEFLAGS is "
        "deciding on stale information.")

P("portable-command-make-parallel", "parallel", "bin/portable-parallel", "command",
  command=["make", "-j4"], toolchain=["make", "cc"],
  prop="the same parallel build requested by a declared argv rather than the environment",
  build_stdout_contains=["PORTABLE_PARALLEL_SEEN=yes"],
  expect=PARALLEL_OK,
  notes="Byte-identical payload to portable-make-parallel-env. The difference "
        "is entirely in lexe.json: build.system 'command' with the -j on the "
        "argv, which puts the parallelism in the SIGNED manifest rather than in "
        "the installing machine's environment.")

P("portable-bare-cc", "bare_cc", "bin/portable-bare-cc", "command",
  command=["cc", "-O2", "-Wall", "-Wextra", "-o", "../bin/portable-bare-cc",
           "main.c"],
  toolchain=["cc"],
  prop="a build that is one compiler invocation and no build system at all",
  expect=dict(COMMON_OK, BUILD_SYSTEM="command", BUILD_DRIVER="none"),
  notes="The smallest possible portable build: no make, no cmake, no shell, no "
        "script in the payload, and the compiler's argv in the signed manifest "
        "rather than in a file the manifest points at. It also shows what that "
        "costs -- there is nowhere to put an `mkdir -p`, so the package has to "
        "SHIP payload/bin, which it does as a .keep file because git cannot "
        "carry an empty directory.")

P("portable-env-flags-default", "env_flags", "bin/portable-env-flags", "make",
  toolchain=["make", "cc"],
  prop="a build that reads an environment variable that is not set, and takes its default",
  expect=dict(COMMON_OK, PROFILE="release", OPTIMIZED="yes", NDEBUG="yes"),
  notes="`PORTABLE_PROFILE ?= release` with nothing in the environment. The "
        "positive half of the pair: the recipe is complete on its own, which is "
        "the property the small build environment exists to check.")

P("portable-env-flags-debug", "env_flags", "bin/portable-env-flags", "make",
  toolchain=["make", "cc"], build_env_extra={"PORTABLE_PROFILE": "debug"},
  prop="the same build with the environment variable set, choosing different flags",
  expect=dict(COMMON_OK, PROFILE="debug", OPTIMIZED="no", NDEBUG="no"),
  notes="Byte-identical payload to portable-env-flags-default; the environment "
        "differs and so does the product. PROFILE is a string the recipe chose "
        "and OPTIMIZED comes from __OPTIMIZE__, which only the compiler can "
        "set -- a recipe that said 'debug' and still compiled at -O2 would show "
        "up as a disagreement between the two, and one value alone could not "
        "show it.")

P("portable-configure-step", "configure_step", "bin/portable-configure-step",
  "make", toolchain=["make", "sh", "cc"],
  prop="a build that generates a header by probing the host before compiling",
  expect=dict(COMMON_OK, BUILD_SHAPE="configure-then-compile",
              CONFIG_STAMP="configured-v1", CONFIG_HAVE_STDINT="1",
              CONFIG_HAVE_UNISTD="1", CONFIG_HAVE_NONSENSE="0",
              CONFIGURE_RAN="yes"),
  notes="The autotools shape without the autotools. main.c includes a header "
        "that DOES NOT EXIST in the shipped package, so anything that assumes "
        "the source tree it received is the source tree the compiler sees is "
        "wrong here. CONFIG_HAVE_NONSENSE is the control: it probes for a "
        "header that cannot exist, and a configure step that answered yes to "
        "everything would look identical without it.")

P("portable-nested-layout", "nested", "bin/portable-nested-layout", "make",
  toolchain=["make", "cc"],
  prop="a source tree three directories deep under sourceDir",
  expect=dict(COMMON_OK, SOURCE_DEPTH="3",
              LEAF_PATH="src/module/deep/leaf.c", NESTED_UNIT_LINKED="yes"),
  notes="The interesting thing is the SHAPE, not the program: an archive or an "
        "installer that flattened the tree would break this without producing a "
        "diagnostic anybody could act on. LEAF_PATH is a literal rather than "
        "__FILE__, because __FILE__ is whatever the compiler was handed and is "
        "therefore an observation -- it is printed as one, beside it.")

# ---- cmake, beyond the flat single-file case ------------------------------
# These four declare `make` in their toolchain as well as `cmake`, which
# portable-cmake does not. cmake's default generator on this host IS Unix
# Makefiles, so `cmake --build` shells out to make and a host without it cannot
# run any of them. The older recipe under-declaring that is left alone rather
# than quietly corrected: a manifest may under-declare its toolchain and still
# build, and having both shapes in the corpus records that.

P("portable-cmake-subdir-install", "cmake_subdir", "bin/portable-cmake-subdir",
  "cmake", toolchain=["cmake", "make", "cc"], cmake_install=True,
  prop="cmake with a subdirectory library and an installed target",
  expect=dict(COMMON_OK, BUILD_SYSTEM="cmake", CMAKE_SHAPE="subdir-install",
              UTIL_VALUE="909", UTIL_ID="cmake-subdir-util-1"),
  expect_relocated=dict(COMMON_OK, BUILD_SYSTEM="cmake",
                        CMAKE_SHAPE="subdir-install", UTIL_VALUE="909",
                        UTIL_ID="cmake-subdir-util-1"),
  notes="Two list files, a target that depends on a target rather than on a "
        "file, and a product that reaches payload/bin through `cmake --install "
        "--prefix <payload>` rather than through an output-directory property. "
        "The two idioms put the file in the same place and fail differently: "
        "an output directory puts it there as a side effect of linking, "
        "install() puts it there only if the install step runs at all -- and "
        "the runtime invoking cmake is what decides whether it does.")

P("portable-cmake-cxx", "cmake_cxx", "bin/portable-cmake-cxx", "cmake",
  toolchain=["cmake", "make", "c++"],
  prop="cmake driving the C++ compiler, with the standard set by a target property",
  needed_contains=["libstdc++.so.6"],
  expect=dict(COMMON_OK, BUILD_SYSTEM="cmake", LANGUAGE="c++",
              CPLUSPLUS="201703", VECTOR_SUM="2080", STRING_VALUE="cmake-cxx"),
  notes="project(... CXX) is what makes cmake probe for a C++ compiler at "
        "configure time rather than a C one. The standard arrives as a cmake "
        "property rather than a -std flag the recipe wrote, so CPLUSPLUS "
        "measures whether that property reached the compiler at all.")

P("portable-cmake-shared-origin", "cmake_shared", "bin/portable-cmake-shared",
  "cmake", toolchain=["cmake", "make", "cc"],
  prop="cmake producing a shared library and an $ORIGIN-relative consumer",
  runpath="$ORIGIN/../lib", rpath_tag="DT_RUNPATH",
  extra_products=["lib/libshared.so"],
  expect=dict(COMMON_OK, BUILD_SYSTEM="cmake", SHARED_VALUE="5150",
              SHARED_ID="cmake-shared-1", SHARED_LIB_RESOLVED="yes"),
  expect_relocated=dict(COMMON_OK, BUILD_SYSTEM="cmake", SHARED_VALUE="5150",
                        SHARED_ID="cmake-shared-1", SHARED_LIB_RESOLVED="yes"),
  notes="The same DT_RUNPATH string as portable-rpath-origin, reached a "
        "completely different way: cmake properties rather than a -Wl,-rpath "
        "the recipe wrote. It matters because cmake's DEFAULT is the "
        "non-relocatable shape -- it links the build tree with an absolute "
        "rpath into its own build directory and rewrites it at install time, "
        "and the rewrite never happens for a product that is copied rather than "
        "installed. BUILD_WITH_INSTALL_RPATH is what puts the final, "
        "$ORIGIN-relative value in at link time.")

P("portable-cmake-fails-configure", "cmake_fails", "bin/portable-cmake-fails",
  "cmake", toolchain=["cmake", "make", "cc"],
  prop="a build that fails at CONFIGURE, a stage the make recipes do not have",
  build_ok=False, product_exists=False, product_kind=None,
  starts_in_build_tree=False, starts_relocated=False,
  leftovers=["cmake-build/CMakeCache.txt"],
  build_stderr_contains=["LexeNonexistentPackage"],
  notes="find_package(... REQUIRED) for a package nobody can install: a missing "
        "dependency discovered at configure time on a host with a perfectly "
        "good compiler. Nothing is compiled and no object exists, and yet a "
        "partial build tree DOES -- cmake writes its cache before it reaches "
        "the failing line -- so a consumer treating 'the build directory has "
        "contents' as evidence of progress is wrong here.")

P("portable-cmake-option-off", "cmake_option", "bin/portable-cmake-option",
  "cmake", toolchain=["cmake", "make", "cc"],
  prop="a cmake option left at its default, producing the smaller product",
  expect=dict(COMMON_OK, BUILD_SYSTEM="cmake", CMAKE_SHAPE="option",
              FEATURE="off"),
  notes="The pair with portable-cmake-option-on is the cmake equivalent of the "
        "env_flags pair: the same source, a different cache variable, and a "
        "different binary.")

P("portable-cmake-option-on", "cmake_option", "bin/portable-cmake-option",
  "cmake", toolchain=["cmake", "make", "cc"],
  cmake_defines=["-DPORTABLE_FEATURE=ON"],
  prop="the same cmake recipe configured with -DPORTABLE_FEATURE=ON",
  expect=dict(COMMON_OK, BUILD_SYSTEM="cmake", CMAKE_SHAPE="option",
              FEATURE="on"),
  notes="Byte-identical payload to portable-cmake-option-off. The -D is on the "
        "CONFIGURE command line, not the compile line, which is why a cmake "
        "build directory cannot be reused across configurations without being "
        "told -- and why this generator gives every recipe its own.")

# ---- hygiene: what an install must and must not carry ---------------------

P("portable-install-hygiene", "hygiene", "bin/portable-hygiene", "make",
  toolchain=["make", "cc"],
  prop="a package whose source directory holds files that must not be installed",
  installed_present=["doc/README.txt", "bin/portable-hygiene"],
  installed_absent=["src/BUILD-ONLY-NOTES.txt", "src/main.c", "src/Makefile",
                    "src/build-stamp.txt", "src/main.o"],
  expect=dict(COMMON_OK, PURPOSE="install-hygiene"),
  expect_relocated=dict(COMMON_OK, PURPOSE="install-hygiene"),
  notes="Three kinds of file that must not reach an installed tree -- shipped "
        "build-only notes, the sources themselves, and intermediates the build "
        "dropped into the source directory while running -- and one file "
        "OUTSIDE the source directory that must. Without the positive half a "
        "check that nothing was installed would pass trivially.")

# ---- paths with spaces and non-ASCII characters ---------------------------

P("portable-unicode-paths-command", "unicode_cmd", "bin/pörtable unicode",
  "command", source_dir="src ünïcode", command=["sh", "build.sh"],
  toolchain=["sh", "cc"],
  prop="spaces and non-ASCII characters in the source dir, the filenames and the product",
  expect=dict(COMMON_OK, PATHS_CONTAIN_SPACES="yes",
              PATHS_CONTAIN_NON_ASCII="yes", UTIL_ANSWER="8888",
              UTIL_ID="unicode-util-1", BOTH_UNITS_LINKED="yes"),
  expect_relocated=dict(COMMON_OK, PATHS_CONTAIN_SPACES="yes",
                        PATHS_CONTAIN_NON_ASCII="yes", UTIL_ANSWER="8888",
                        UTIL_ID="unicode-util-1", BOTH_UNITS_LINKED="yes"),
  notes="Not exotic: it is what happens the first time a package is written by "
        "somebody whose language is not English, or unpacked under a directory "
        "called My Documents. The schema's relative-payload-path rules permit "
        "all of it -- they forbid NUL, backslash, a leading slash, a drive "
        "designator and a .. segment, and say nothing about spaces or "
        "non-ASCII -- so a manifest like this is well formed and everything "
        "that builds a command line by pasting strings together breaks on it. "
        "The build is a script because every path in it has to be quoted; see "
        "portable-unicode-paths-make for why it could not be a Makefile.")

P("portable-unicode-paths-make", "unicode_make",
  "bin/portable path with space", "make", source_dir="src with space",
  toolchain=["make", "cc"],
  prop="a make build in a directory with a space, producing a product with a space",
  expect=dict(COMMON_OK, SOURCE_DIR_HAS_SPACE="yes",
              PRODUCT_NAME_HAS_SPACE="yes"),
  expect_relocated=dict(COMMON_OK, SOURCE_DIR_HAS_SPACE="yes",
                        PRODUCT_NAME_HAS_SPACE="yes"),
  notes="This works, and only because of how the Makefile is written -- which "
        "is the finding. GNU make separates targets and prerequisites with "
        "whitespace and has no quoting that survives it, so a spaced path "
        "cannot be a target or a prerequisite at all. The way out is to stop "
        "naming it: `all` is PHONY with no file prerequisites and the spaced "
        "path appears only inside a recipe line, where the SHELL parses it and "
        "ordinary double quotes work. The cost is that the product is rebuilt "
        "unconditionally, because make no longer knows what the rule produces. "
        "`make -C 'src with space'` itself is fine: that path is an argument to "
        "make, never a token in a makefile.")

# ---- a second foreign product ---------------------------------------------

P("portable-product-pe-dll", "product_pe", "bin/portable-product-pe-dll.dll",
  "make", toolchain=["make", "x86_64-w64-mingw32-gcc"],
  architectures=["x86_64"], makefile_variant="dll",
  prop="a build that succeeds and produces a Windows DLL, which is not an entrypoint",
  product_kind="pe",
  starts_in_build_tree=False, starts_relocated=False,
  host_dependency="mingw-w64 installed on this host. The DECLARATION that the "
                  "product does not start is about the file rather than the "
                  "host: binfmt_misc hands PE files to Windows here (see "
                  "portable-product-pe), and Windows will not execute a DLL as "
                  "a process either.",
  notes="Same source as portable-product-pe, linked -shared. file(1) calls it a "
        "'PE32+ executable (DLL)' -- a sentence containing the word executable "
        "about something that cannot be executed, which is the same trap as the "
        "ELF shared-object specimen in the other format. The pair covers 'the "
        "build succeeded and the product is foreign' against 'the build "
        "succeeded and the product is not a program'.")


# --------------------------------------------------------------------------
# Assembling a package from a recipe
# --------------------------------------------------------------------------

def manifest_for(spec):
    """The lexe.json a portable package carries. Generated from the table rather
    than hand-written ninety-four times: the table is the source of truth for what
    each recipe declares, and a manifest that drifted from it would be a fixture
    that lies."""
    build = {
        "system": spec["build_system"],
        "sourceDir": spec["source_dir"],
        "toolchain": list(spec["toolchain"]),
    }
    if spec["build_system"] == "command":
        build["command"] = list(spec["build_command"])
    return {
        "lexeVersion": "0.1",
        "id": "dev.lexe.workload." + spec["id"],
        "name": "Lexe workload " + spec["id"],
        "version": "1.0.0",
        "publisher": {
            "name": "lexe workload factory",
            "publicKey": "AUTO",
            "website": "https://example.invalid/lexe-workloads",
        },
        "role": "application",
        "applicationType": "portable",
        "architectures": list(spec["architectures"]),
        "entrypoint": {
            "executable": spec["entrypoint"],
            "arguments": list(spec["arguments"]),
        },
        "build": build,
        "execution": {"missionCritical": False, "allowedChains": ["native"]},
        "launch": {"mode": "console", "singleInstance": False},
        "install": {"scope": "user", "mode": "bundled"},
        "integration": {"desktopEntry": False, "categories": ["Development"]},
        "permissions": [],
    }


def assemble(spec, recipes_dir, dest):
    """Write the shipped package: lexe.json plus the payload tree, and nothing
    else. What ships is what a publisher would sign."""
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    src_payload = os.path.join(recipes_dir, spec["recipe_dir"], "payload")
    shutil.copytree(src_payload, os.path.join(dest, "payload"))
    if spec["makefile_variant"]:
        variant = os.path.join(recipes_dir, spec["recipe_dir"], "makefiles",
                               "Makefile." + spec["makefile_variant"])
        shutil.copy2(variant,
                     os.path.join(dest, "payload", spec["source_dir"],
                                  spec["variant_dest"]))
    manifest = manifest_for(spec)
    with open(os.path.join(dest, "lexe.json"), "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    return manifest


def validate_manifest(manifest, schema):
    if schema is None:
        return {"checked": False, "valid": None, "errors": ["schema not loaded"]}
    try:
        import jsonschema
    except ImportError:
        return {"checked": False, "valid": None, "errors": ["jsonschema not installed"]}
    validator = jsonschema.Draft202012Validator(schema)
    errors = ["%s: %s" % ("/".join(str(p) for p in e.path) or "<root>", e.message)
              for e in validator.iter_errors(manifest)]
    return {"checked": True, "valid": not errors, "errors": errors[:10]}


# --------------------------------------------------------------------------
# The direct build
# --------------------------------------------------------------------------

def build_env(root, spec=None):
    """A deliberately small environment. CC and CFLAGS are NOT set, so the `?=`
    defaults in each recipe are what run; a build that only works because this
    generator exported something is a build whose recipe is incomplete.

    `spec["build_env_extra"]` is the one exception, and it is an exception with a
    declaration attached: the env_flags pair and the parallel-make recipe exist
    precisely to record what a build does when a variable it reads is set and
    when it is not. The merged environment is stored in `build.env` either way,
    so no reader has to infer it."""
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "SHELL": "/bin/sh",
        "HOME": os.path.join(root, "home"),
        "TMPDIR": os.path.join(root, "tmp"),
    }
    for d in ("home", "tmp"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    if spec:
        env.update(spec.get("build_env_extra") or {})
    return env


def build_commands(spec, payload_root):
    """The exact argv sequence this generator runs, and the directory it runs it
    in. For `make` this mirrors what the documented invocation is -- `make -C
    <sourceDir>` from the payload root. For `cmake` and `command` the sequence is
    THIS generator's choice and is recorded as such: how .LEXE invokes a driver
    is not something a workload may assume."""
    src = spec["source_dir"]
    if spec["build_system"] == "make":
        return [{"argv": ["make", "-C", src], "cwd": payload_root}]
    if spec["build_system"] == "cmake":
        steps = [
            {"argv": ["cmake", "-S", src, "-B", "cmake-build",
                      "-DCMAKE_BUILD_TYPE=Release"] + list(spec["cmake_defines"]),
             "cwd": payload_root},
            {"argv": ["cmake", "--build", "cmake-build"], "cwd": payload_root},
        ]
        if spec["cmake_install"]:
            # `cmake --install` with the payload root as the prefix: the
            # install(TARGETS ... DESTINATION bin) in the list file is then what
            # decides where the entrypoint lands, rather than an output-directory
            # property. Both idioms are in the corpus because both are common and
            # they fail differently.
            steps.append({"argv": ["cmake", "--install", "cmake-build",
                                   "--prefix", payload_root],
                          "cwd": payload_root})
        return steps
    if spec["build_system"] == "command":
        return [{"argv": list(spec["build_command"]),
                 "cwd": os.path.join(payload_root, src)}]
    raise ValueError("unknown build system %r" % spec["build_system"])


def run_build(spec, build_root):
    payload_root = os.path.join(build_root, "payload")
    env = build_env(build_root, spec)
    steps = []
    ok = True
    t0 = time.time()
    for step in build_commands(spec, payload_root):
        s0 = time.time()
        try:
            r = subprocess.run(step["argv"], cwd=step["cwd"], env=env,
                               capture_output=True, text=True,
                               timeout=BUILD_TIMEOUT_S)
            rc, so, se, timed_out = r.returncode, r.stdout, r.stderr, False
        except subprocess.TimeoutExpired as e:
            rc, so, se, timed_out = None, e.stdout or "", e.stderr or "", True
        except FileNotFoundError as e:
            rc, so, se, timed_out = None, "", "argv[0] not found: %s" % e, False
        steps.append({
            "argv": step["argv"],
            "cwd": step["cwd"],
            "exit_code": rc,
            "timed_out": timed_out,
            "seconds": round(time.time() - s0, 2),
            "stdout": (so or "")[-4000:],
            "stderr": (se or "")[-4000:],
        })
        if rc != 0:
            ok = False
            break
    return {
        "system": spec["build_system"],
        "env": env,
        "steps": steps,
        "ok": ok,
        "seconds": round(time.time() - t0, 2),
    }


def probe_toolchain(names):
    out = []
    for name in names:
        path = shutil.which(name, path="/usr/bin:/bin")
        out.append({"name": name, "path": path,
                    "version": tool_version(path) if path else None})
    return out


# --------------------------------------------------------------------------
# The direct execution baselines
# --------------------------------------------------------------------------

BASE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "TERM": "dumb", "SHELL": "/bin/sh"}


def run_product(spec, exe, rundir, label):
    """Direct execution. LD_LIBRARY_PATH is deliberately NOT set: whether the
    product finds its own library has to be a property of the product."""
    os.makedirs(rundir, exist_ok=True)
    env = dict(BASE_ENV)
    env["HOME"] = os.path.join(rundir, "home")
    env["TMPDIR"] = os.path.join(rundir, "tmp")
    for d in ("home", "tmp"):
        os.makedirs(os.path.join(rundir, d), exist_ok=True)
    env["FIXTURE_ID"] = spec["id"]
    argv = [exe] + list(spec["arguments"])
    t0 = time.time()
    timed_out = False
    try:
        p = subprocess.run(argv, cwd=rundir, env=env, input=b"",
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=RUN_TIMEOUT_S)
        rc, so, se = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        rc, so, se = None, e.stdout or b"", e.stderr or b""
    except OSError as e:
        return {
            "label": label, "argv": argv, "launched": False,
            "os_error": "%s: %s" % (type(e).__name__, e),
            "exit_code": None, "signal": None, "started": False,
        }
    kv, det, repeats = parse_oracle(so.decode("utf-8", "replace"))
    return {
        "label": label,
        "argv": argv,
        "launched": True,
        "exit_code": rc if (rc is None or rc >= 0) else None,
        "signal": (-rc) if (rc is not None and rc < 0) else None,
        "timed_out": timed_out,
        "duration_ms": round((time.time() - t0) * 1000.0, 1),
        "stdout_bytes": len(so),
        "stderr_bytes": len(se),
        "stdout_sha256": sha256_bytes(so),
        "started": "FIXTURE_ID" in kv,
        "oracle": kv,
        "oracle_deterministic_lines": det,
        "oracle_repeated_keys": repeats,
        "observations": {k[4:]: v for k, v in kv.items() if k.startswith("OBS_")},
        "stdout_head": so[:2048].decode("utf-8", "replace"),
        "stderr_head": se[:2048].decode("utf-8", "replace"),
    }


def promote(payload_root, source_dir, dest):
    """What an install would promote: everything the build produced under the
    payload EXCEPT the source directory. The relative layout is preserved,
    because that is what $ORIGIN depends on."""
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    promoted = []
    for name in sorted(os.listdir(payload_root)):
        if name in (source_dir, "cmake-build"):
            continue
        src = os.path.join(payload_root, name)
        dst = os.path.join(dest, name)
        if os.path.isdir(src):
            shutil.copytree(src, dst, symlinks=True)
        else:
            shutil.copy2(src, dst)
        promoted.append(name)
    return promoted


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------

def subst(value, rec):
    """{SRCDIR} and {INSTALLDIR} in a declaration are the two absolute paths that
    cannot be known until the build has a directory. Everything else in a
    declaration is a literal."""
    if not isinstance(value, str):
        return value
    return (value.replace("{SRCDIR}", rec.get("source_dir_abs", ""))
                 .replace("{INSTALLDIR}", rec.get("installed_root_abs", "")))


def check_oracle(label, want, run, rec, problems):
    for key, w in want.items():
        w = subst(w, rec)
        got = run["oracle"].get(key, "<absent>")
        if got != w:
            problems.append("%s%s: declared %r, observed %r" % (label, key, w, got))


def verdict_for(spec, rec):
    d = spec["declared"]
    problems = []

    probe = rec["toolchain_probe"]
    all_present = all(t["path"] for t in probe)
    if all_present != d["toolchain_present"]:
        problems.append("toolchain presence: declared %s, probed %s (%s)"
                        % (d["toolchain_present"], all_present,
                           ", ".join("%s=%s" % (t["name"], t["path"] or "ABSENT")
                                     for t in probe)))

    if rec["build"]["ok"] != d["build_succeeds"]:
        last = rec["build"]["steps"][-1] if rec["build"]["steps"] else {}
        problems.append("build: declared ok=%s, observed ok=%s (exit=%r)"
                        % (d["build_succeeds"], rec["build"]["ok"],
                           last.get("exit_code")))

    build_out = "\n".join(s.get("stdout") or "" for s in rec["build"]["steps"])
    build_err = "\n".join(s.get("stderr") or "" for s in rec["build"]["steps"])
    for want in d["build_stdout_contains"]:
        if want not in build_out:
            problems.append("build stdout does not contain %r" % want)
    for want in d["build_stderr_contains"]:
        if want not in build_err:
            problems.append("build stderr does not contain %r" % want)

    product = rec["product"]
    if product["exists"] != d["product_exists"]:
        problems.append("product %s: declared exists=%s, observed %s"
                        % (spec["entrypoint"], d["product_exists"], product["exists"]))

    if product["exists"]:
        if d["product_kind"] and product["kind"] != d["product_kind"]:
            problems.append("product kind: declared %r, observed %r (file says %r)"
                            % (d["product_kind"], product["kind"],
                               product["elf"].get("file_says")))
        want_runpath = subst(d["runpath"], rec)
        got_runpath = product["elf"].get("runpath") or product["elf"].get("rpath")
        if want_runpath != got_runpath:
            problems.append("runpath: declared %r, observed %r"
                            % (want_runpath, got_runpath))
        if d["rpath_tag"] and product["elf"].get("rpath_tag") != d["rpath_tag"]:
            problems.append("rpath tag: declared %s, observed %s"
                            % (d["rpath_tag"], product["elf"].get("rpath_tag")))
        if d["product_min_bytes"] and product["size_bytes"] < d["product_min_bytes"]:
            problems.append("product is %d bytes, declared at least %d"
                            % (product["size_bytes"], d["product_min_bytes"]))
        if d["product_max_bytes"] and product["size_bytes"] > d["product_max_bytes"]:
            problems.append("product is %d bytes, declared at most %d"
                            % (product["size_bytes"], d["product_max_bytes"]))

        elf = product["elf"]
        if d["e_type"] and not (elf.get("e_type") or "").startswith(d["e_type"]):
            problems.append("ELF e_type: declared %s, observed %r"
                            % (d["e_type"], elf.get("e_type")))
        if d["pie"] is not None and bool(elf.get("pie")) != d["pie"]:
            problems.append("pie: declared %s, observed %s"
                            % (d["pie"], bool(elf.get("pie"))))
        if d["interpreter"] is not None:
            got = "present" if elf.get("interpreter") else "absent"
            if got != d["interpreter"]:
                problems.append("program interpreter: declared %s, observed %s (%r)"
                                % (d["interpreter"], got, elf.get("interpreter")))
        for lib in d["needed_contains"]:
            if lib not in (elf.get("needed") or []):
                problems.append("DT_NEEDED does not contain %r (observed %r)"
                                % (lib, elf.get("needed")))
        if d["needed_empty"] is not None:
            got = not (elf.get("needed") or [])
            if got != d["needed_empty"]:
                problems.append("DT_NEEDED empty: declared %s, observed %s (%r)"
                                % (d["needed_empty"], got, elf.get("needed")))
        if d["has_symtab"] is not None and elf.get("is_elf") \
           and bool(elf.get("has_symtab")) != d["has_symtab"]:
            problems.append("has .symtab: declared %s, observed %s"
                            % (d["has_symtab"], bool(elf.get("has_symtab"))))
        if d["product_mode"] and product["mode"] != d["product_mode"]:
            problems.append("product mode: declared %s, observed %s"
                            % (d["product_mode"], product["mode"]))

    for rel in d["extra_products"]:
        if rel not in rec["build_products"]:
            problems.append("declared extra product %s was not produced" % rel)
    for rel in d["leftovers_after_failed_build"]:
        if rel not in rec["build_products"]:
            problems.append("declared leftover %s of the failed build is absent" % rel)

    for label, key in (("in build tree", "starts_in_build_tree"),
                       ("relocated", "starts_after_build_tree_removed")):
        run = rec["runs"].get("in_build_tree" if key == "starts_in_build_tree"
                              else "after_build_tree_removed")
        want = d[key]
        got = bool(run and run.get("started"))
        if want != got:
            problems.append("%s: declared starts=%s, observed started=%s (exit=%r)"
                            % (label, want, got, run.get("exit_code") if run else None))

    run = rec["runs"].get("in_build_tree")
    if run and run.get("started"):
        if run.get("exit_code") != d["exit_code"]:
            problems.append("exit code in build tree: declared %r, observed %r"
                            % (d["exit_code"], run.get("exit_code")))
        if run.get("signal") != d["signal"]:
            problems.append("terminating signal in build tree: declared %r, observed %r"
                            % (d["signal"], run.get("signal")))
        for want in d["run_stderr_contains"]:
            if want not in (run.get("stderr_head") or ""):
                problems.append("run stderr does not contain %r" % want)
        check_oracle("", d["expect"], run, rec, problems)

    reloc = rec["runs"].get("after_build_tree_removed")
    if reloc and reloc.get("started"):
        if reloc.get("exit_code") != d["relocated_exit_code"]:
            problems.append("exit code relocated: declared %r, observed %r"
                            % (d["relocated_exit_code"], reloc.get("exit_code")))
        if reloc.get("signal") != d["relocated_signal"]:
            problems.append("terminating signal relocated: declared %r, observed %r"
                            % (d["relocated_signal"], reloc.get("signal")))
        check_oracle("relocated ", d["expect_relocated"], reloc, rec, problems)

    installed = (rec.get("installed") or {}).get("files") or {}
    for rel in d["installed_present"]:
        if rel not in installed:
            problems.append("declared installed file %s is absent from the "
                            "promoted tree" % rel)
    for rel in d["installed_absent"]:
        if rel in installed:
            problems.append("%s must NOT be installed and is in the promoted tree"
                            % rel)

    if rec["manifest_schema"]["checked"] and not rec["manifest_schema"]["valid"]:
        problems.append("manifest fails schema: %s"
                        % "; ".join(rec["manifest_schema"]["errors"]))
    return problems


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def process(spec, out, recipes_dir, schema):
    rec = {k: v for k, v in spec.items()}
    pkg_dir = os.path.join(out, "pkg", spec["id"])
    build_root = os.path.join(out, "build", spec["id"])
    vanished_root = os.path.join(out, "vanished", spec["id"])
    installed_root = os.path.join(out, "installed", spec["id"])

    manifest = assemble(spec, recipes_dir, pkg_dir)
    rec["manifest"] = manifest
    rec["manifest_schema"] = validate_manifest(manifest, schema)
    rec["package"] = {
        "dir": pkg_dir,
        "files": tree_files(pkg_dir),
    }
    rec["package"]["total_bytes"] = sum(v["size"] for v in rec["package"]["files"].values())

    rec["toolchain_probe"] = probe_toolchain(spec["toolchain"])

    if os.path.exists(build_root):
        shutil.rmtree(build_root)
    shutil.copytree(pkg_dir, build_root)
    payload_root = os.path.join(build_root, "payload")
    rec["source_dir_abs"] = os.path.join(payload_root, spec["source_dir"])
    rec["installed_root_abs"] = installed_root

    before = set(tree_files(payload_root))
    rec["build"] = run_build(spec, build_root)
    after = tree_files(payload_root)
    rec["build_products"] = {k: v for k, v in sorted(after.items()) if k not in before}

    product_path = os.path.join(payload_root, spec["entrypoint"])
    if os.path.exists(product_path):
        facts = elf_facts(product_path)
        rec["product"] = {
            "declared_path": spec["entrypoint"],
            "exists": True,
            "built_path": product_path,
            "size_bytes": os.path.getsize(product_path),
            "sha256": sha256_file(product_path),
            "mode": oct(os.stat(product_path).st_mode & 0o777),
            "elf": facts,
            "kind": classify_product(facts),
            "ldd_in_build_tree": ldd_says(product_path),
        }
    else:
        rec["product"] = {"declared_path": spec["entrypoint"], "exists": False,
                          "elf": {}, "kind": None, "size_bytes": 0}

    rec["runs"] = {}
    if rec["product"]["exists"]:
        rec["runs"]["in_build_tree"] = run_product(
            spec, product_path, os.path.join(build_root, "rundir"), "in_build_tree")

        rec["promoted"] = promote(payload_root, spec["source_dir"], installed_root)
        installed_exe = os.path.join(installed_root, spec["entrypoint"])
        # The build tree goes away, exactly as a staging directory does when an
        # install commits. Renamed rather than deleted so it stays inspectable.
        if os.path.exists(vanished_root):
            shutil.rmtree(vanished_root)
        os.makedirs(os.path.dirname(vanished_root), exist_ok=True)
        shutil.move(build_root, vanished_root)
        try:
            rec["installed"] = {
                "dir": installed_root,
                "files": tree_files(installed_root),
                "ldd": ldd_says(installed_exe) if os.path.exists(installed_exe) else None,
            }
            rec["runs"]["after_build_tree_removed"] = run_product(
                spec, installed_exe, os.path.join(out, "rundir", spec["id"]),
                "after_build_tree_removed")
        finally:
            shutil.move(vanished_root, build_root)
    else:
        rec["promoted"] = []
        rec["installed"] = None

    problems = verdict_for(spec, rec)
    rec["verdict"] = {"status": "baseline-ok" if not problems else "baseline-mismatch",
                      "problems": problems}
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/lexe-workloads-portable")
    ap.add_argument("--recipes", default=DEFAULT_RECIPES)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument("--only", default=None, help="substring filter on recipe id")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 4) // 4))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    recipes_dir = os.path.abspath(args.recipes)
    os.makedirs(out, exist_ok=True)

    schema = None
    schema_sha = None
    if os.path.exists(args.schema):
        with open(args.schema) as f:
            schema = json.load(f)
        schema_sha = sha256_file(args.schema)

    chosen = [s for s in RECIPES if not args.only or args.only in s["id"]]
    # Taken HERE rather than in host_facts(), which runs after the pool has
    # finished. The first version read both ends from host_facts() and the two
    # numbers came out byte-identical, which is what gave it away: a field named
    # loadavg_at_start that is measured at the end is worse than no field, since
    # it looks like evidence that the run was not under load.
    load_at_start = list(os.getloadavg())
    t0 = time.time()
    results = []
    with futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {pool.submit(process, s, out, recipes_dir, schema): s for s in chosen}
        for fut in futures.as_completed(futs):
            spec = futs[fut]
            try:
                rec = fut.result()
            except Exception as exc:   # a generator bug must not look like a recipe bug
                rec = {"id": spec["id"],
                       "verdict": {"status": "generator-error", "problems": [repr(exc)]}}
            results.append(rec)
            if not args.quiet:
                v = rec.get("verdict", {})
                print("%-18s %s" % (v.get("status", "?"), rec["id"]))
                for p in v.get("problems", [])[:8]:
                    print("                   ! %s" % p)
    results.sort(key=lambda r: r["id"])
    elapsed = round(time.time() - t0, 1)

    counts = {}
    for r in results:
        counts[r["verdict"]["status"]] = counts.get(r["verdict"]["status"], 0) + 1

    # The rpath table: what each idiom actually produced, side by side. It is the
    # reason this family exists, so it is a first-class field rather than
    # something a reader has to assemble from ninety-four records.
    rpath_table = []
    for r in results:
        if not r.get("product", {}).get("exists"):
            continue
        elf = r["product"]["elf"]
        if not (elf.get("runpath") or elf.get("rpath")):
            continue
        runs = r.get("runs", {})
        rpath_table.append({
            "id": r["id"],
            "makefile_variant": r.get("makefile_variant"),
            "rpath_literal_in_recipe": r.get("property"),
            "tag": elf.get("rpath_tag"),
            "value_in_built_file": elf.get("runpath") or elf.get("rpath"),
            "starts_in_build_tree": bool(runs.get("in_build_tree", {}).get("started")),
            "starts_after_build_tree_removed":
                bool(runs.get("after_build_tree_removed", {}).get("started")),
        })

    index = {
        "schema": "lexe.workload.portable.index/1",
        "schema_notes": {
            "declared": "written by hand before the recipe was ever built; the "
                        "generator checks the observation against it",
            "build": "the DIRECT build, outside .LEXE, in a clean environment; "
                     "`steps` is the exact argv sequence and where it ran",
            "runs.in_build_tree": "the product executed from the tree that built it",
            "runs.after_build_tree_removed": "the promoted product executed from a "
                        "different directory with the build tree renamed away -- "
                        "the measurement that finds a baked-in absolute path",
            "product.kind": "decided from file(1) and readelf, not from the flags "
                        "the recipe used",
            "verdict.status": "baseline-ok means the recipe is admitted to the "
                        "corpus; baseline-mismatch means the DECLARATION or the "
                        "recipe is wrong and it must not be used as evidence",
        },
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generator": {
            "file": os.path.basename(__file__),
            "sha256": sha256_file(os.path.abspath(__file__)),
            "recipes_dir": recipes_dir,
            "manifest_schema": args.schema,
            "manifest_schema_sha256": schema_sha,
            "wall_seconds": elapsed,
            "jobs": args.jobs,
            "loadavg_at_end": list(os.getloadavg()),
        },
        # loadavg_at_start is measured before the first build starts and
        # loadavg_at_end after the last one finishes, because runs.*.duration_ms
        # is in this file and a duration taken under load is not a measurement
        # of anything. No declaration in this corpus asserts a duration; these
        # two numbers are what let a reader decide whether the observed ones are
        # worth reading at all.
        "host": dict(host_facts(), loadavg_at_start=load_at_start),
        "host_tools": {name: {"path": shutil.which(name, path="/usr/bin:/bin"),
                              "version": (tool_version(name)
                                          if shutil.which(name, path="/usr/bin:/bin")
                                          else None)}
                       for name in ("make", "cmake", "cc", "c++", "gcc", "g++",
                                    "sh", "x86_64-w64-mingw32-gcc")},
        "corpus_root": out,
        "counts": {"recipes": len(results), **counts},
        "rpath_variant_table": rpath_table,
        "recipes": results,
    }
    index_path = os.path.join(out, "index.json")
    with open(index_path, "w") as f:
        json.dump(index, f, indent=1, sort_keys=False)
    print("\n%d recipes, %s, %.1fs -> %s"
          % (len(results), ", ".join("%s=%d" % kv for kv in sorted(counts.items())),
             elapsed, index_path))
    return 0 if counts.get("baseline-ok", 0) == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())

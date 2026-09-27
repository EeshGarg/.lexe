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
            "toolchain_present": kw.get("toolchain_present", True),
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


# --------------------------------------------------------------------------
# Assembling a package from a recipe
# --------------------------------------------------------------------------

def manifest_for(spec):
    """The lexe.json a portable package carries. Generated from the table rather
    than hand-written eighteen times: the table is the source of truth for what
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
                     os.path.join(dest, "payload", spec["source_dir"], "Makefile"))
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

def build_env(root):
    """A deliberately small environment. CC and CFLAGS are NOT set, so the `?=`
    defaults in each recipe are what run; a build that only works because this
    generator exported something is a build whose recipe is incomplete."""
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
        return [
            {"argv": ["cmake", "-S", src, "-B", "cmake-build",
                      "-DCMAKE_BUILD_TYPE=Release"], "cwd": payload_root},
            {"argv": ["cmake", "--build", "cmake-build"], "cwd": payload_root},
        ]
    if spec["build_system"] == "command":
        return [{"argv": list(spec["build_command"]),
                 "cwd": os.path.join(payload_root, src)}]
    raise ValueError("unknown build system %r" % spec["build_system"])


def run_build(spec, build_root):
    payload_root = os.path.join(build_root, "payload")
    env = build_env(build_root)
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

    product = rec["product"]
    if product["exists"] != d["product_exists"]:
        problems.append("product %s: declared exists=%s, observed %s"
                        % (spec["entrypoint"], d["product_exists"], product["exists"]))

    if product["exists"]:
        if d["product_kind"] and product["kind"] != d["product_kind"]:
            problems.append("product kind: declared %r, observed %r (file says %r)"
                            % (d["product_kind"], product["kind"],
                               product["elf"].get("file_says")))
        want_runpath = d["runpath"]
        if want_runpath is not None:
            want_runpath = want_runpath.replace("{SRCDIR}", rec["source_dir_abs"])
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
        for key, want in d["expect"].items():
            got = run["oracle"].get(key, "<absent>")
            if got != want:
                problems.append("%s: declared %r, observed %r" % (key, want, got))

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
    # something a reader has to assemble from eighteen records.
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
        },
        "host": host_facts(),
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

#!/usr/bin/env python3
"""Which specimens in the ELF corpus cannot start once the corpus moves?

A specimen that cannot start covers nothing. This is a MEASUREMENT, not a
generator: it builds the corpus at one path, renames the whole tree to another
path, and runs every specimen from the new location with

  * argv rewritten correctly for the new location (so a consumer doing its job
    properly is assumed), and
  * LD_LIBRARY_PATH NOT set (so whether a binary finds its libraries is a
    property of the binary),

and reports who started and who did not. "Started" means the specimen's own
FIXTURE_ID line appeared on its oracle stream, which is the only evidence that
control reached main.

Usage:
    python3 audit_relocation.py --generator <path to generate.py> \
        --work /tmp/rolec/audit [--jobs N]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

BASE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "TERM": "dumb", "SHELL": "/bin/sh"}


def subst(items, mapping):
    out = []
    for it in items:
        for k, v in mapping.items():
            it = it.replace("{%s}" % k, v)
        out.append(it)
    return out


def run_one(spec, new_root, rundir, set_ld_library_path):
    binary = spec["build"]["target"]
    env = dict(BASE_ENV)
    env["HOME"] = os.path.join(rundir, "home")
    env["TMPDIR"] = os.path.join(rundir, "tmp")
    env["XDG_DATA_HOME"] = os.path.join(rundir, "xdg", "data")
    env["XDG_CONFIG_HOME"] = os.path.join(rundir, "xdg", "config")
    env["XDG_CACHE_HOME"] = os.path.join(rundir, "xdg", "cache")
    for d in ("home", "tmp", "xdg/data", "xdg/config", "xdg/cache"):
        os.makedirs(os.path.join(rundir, *d.split("/")), exist_ok=True)
    env["FIXTURE_ID"] = spec["id"]
    if set_ld_library_path:
        env["LD_LIBRARY_PATH"] = os.path.join(new_root, "lib")
    env.update(spec.get("env") or {})
    mapping = {"LIBDIR": os.path.join(new_root, "lib"),
               "HELPER": os.path.join(new_root, "bin", "helper_child")}
    argv = [binary] + subst(list(spec.get("argv") or []), mapping)
    for rel, content in (spec.get("staged_files") or {}).items():
        path = os.path.join(rundir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    try:
        p = subprocess.run(argv, cwd=rundir, env=env, input=b"",
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=float(spec.get("timeout_s") or 60.0))
        rc, so, se = p.returncode, p.stdout, p.stderr
        timed_out = False
    except subprocess.TimeoutExpired as e:
        rc, so, se, timed_out = None, e.stdout or b"", e.stderr or b""
        timed_out = True
    except OSError as e:
        return {"launched": False, "started": False, "error": repr(e),
                "exit_code": None, "signal": None, "stderr_head": ""}
    stream = se if spec["declared"]["oracle_stream"] == "stderr" else so
    text = stream.decode("utf-8", "replace")
    return {
        "launched": True,
        "started": ("FIXTURE_ID=" in text),
        "exit_code": rc if (rc is None or rc >= 0) else None,
        "signal": (-rc) if (rc is not None and rc < 0) else None,
        "timed_out": timed_out,
        "result": next((l.split("=", 1)[1] for l in text.split("\n")
                        if l.startswith("RESULT=")), None),
        "stderr_head": se.decode("utf-8", "replace")[:300].strip(),
        "argv": argv,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--generator", required=True)
    ap.add_argument("--work", default="/tmp/rolec/audit")
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--skip-generate", action="store_true")
    args = ap.parse_args()

    work = os.path.abspath(args.work)
    root_a = os.path.join(work, "built-here")
    root_b = os.path.join(work, "moved-there-and-the-original-is-gone")
    runs = os.path.join(work, "runs")

    if not args.skip_generate:
        for d in (root_a, root_b, runs):
            if os.path.exists(d):
                shutil.rmtree(d)
        os.makedirs(work, exist_ok=True)
        t0 = time.time()
        r = subprocess.run([sys.executable, args.generator, "--out", root_a,
                            "--jobs", str(args.jobs), "--quiet"],
                           capture_output=True, text=True)
        print("generated in %.1fs (generator exit %d)" % (time.time() - t0, r.returncode))
        if not os.path.exists(os.path.join(root_a, "index.json")):
            print(r.stdout[-3000:]); print(r.stderr[-3000:])
            return 2
        shutil.move(root_a, root_b)

    index = json.load(open(os.path.join(root_b, "index.json")))
    # Every recorded path points at the directory the corpus was BUILT in, which
    # no longer exists. Rewriting them is what a consumer that relocates a tree
    # would do; whether the BINARY can cope is the measurement.
    raw = json.dumps(index)
    index = json.loads(raw.replace(root_a, root_b))

    rows = []
    for spec in index["specimens"]:
        if spec["verdict"]["status"] != "baseline-ok":
            continue
        if not spec.get("build", {}).get("target"):
            continue
        rundir = os.path.join(runs, spec["id"])
        if os.path.exists(rundir):
            shutil.rmtree(rundir)
        os.makedirs(rundir)
        without = run_one(spec, root_b, rundir, set_ld_library_path=False)
        with_ld = None
        if not without["started"]:
            rundir2 = rundir + "-with-ld-library-path"
            if os.path.exists(rundir2):
                shutil.rmtree(rundir2)
            os.makedirs(rundir2)
            with_ld = run_one(spec, root_b, rundir2, set_ld_library_path=True)
        elf = (spec.get("binary") or {}).get("elf") or {}
        rows.append({
            "id": spec["id"],
            "family": spec["family"],
            "property": spec["property"],
            "rpath": elf.get("rpath"),
            "runpath": elf.get("runpath"),
            "needed": elf.get("needed"),
            "stage": spec.get("stage"),
            "declared_argv": spec.get("argv"),
            "baseline_result": (spec.get("baseline") or {}).get("runs", [{}])[-1]
                               .get("oracle", {}).get("RESULT"),
            "relocated": without,
            "relocated_with_ld_library_path": with_ld,
        })

    out = {
        "schema": "lexe.workload.relocation-audit/1",
        "what_this_measures": "whether each baseline-ok specimen still reaches "
                              "main() when the whole corpus tree is renamed and "
                              "the original path no longer exists, with argv "
                              "rewritten for the new path and LD_LIBRARY_PATH unset",
        "built_at": root_a,
        "moved_to": root_b,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "counts": {
            "examined": len(rows),
            "started": sum(1 for r in rows if r["relocated"]["started"]),
            "did_not_start": sum(1 for r in rows if not r["relocated"]["started"]),
            "did_not_start_but_would_with_ld_library_path":
                sum(1 for r in rows
                    if not r["relocated"]["started"]
                    and (r["relocated_with_ld_library_path"] or {}).get("started")),
        },
        "specimens": rows,
    }
    path = os.path.join(work, "relocation-audit.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)

    print()
    print("examined %d baseline-ok specimens" % out["counts"]["examined"])
    print("  started after relocation : %d" % out["counts"]["started"])
    print("  did NOT start            : %d" % out["counts"]["did_not_start"])
    print("  of those, would start with LD_LIBRARY_PATH set: %d"
          % out["counts"]["did_not_start_but_would_with_ld_library_path"])
    print()
    for r in rows:
        if r["relocated"]["started"]:
            continue
        w = r["relocated_with_ld_library_path"] or {}
        print("DID NOT START  %s" % r["id"])
        print("   property : %s" % r["property"])
        print("   rpath=%r runpath=%r" % (r["rpath"], r["runpath"]))
        print("   exit=%r signal=%r  with LD_LIBRARY_PATH: started=%s"
              % (r["relocated"]["exit_code"], r["relocated"]["signal"],
                 w.get("started")))
        print("   stderr: %s" % r["relocated"]["stderr_head"].replace("\n", " | ")[:220])
    print()
    print("also: specimens whose argv names an absolute path inside the corpus")
    for r in rows:
        for a in (r["declared_argv"] or []):
            if "{LIBDIR}" in a or "{HELPER}" in a:
                print("   %-34s argv=%s" % (r["id"], r["declared_argv"]))
                break
    print()
    print("-> %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

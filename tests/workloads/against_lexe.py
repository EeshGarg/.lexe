#!/usr/bin/env python3
"""against_lexe.py -- drive a workload corpus THROUGH `.LEXE` and compare the
result against the direct-execution baseline the corpus recorded.

This is the consumer side of the three-role model. `generate.py` /
`generate_pe.py` (Role C) manufacture legitimate programs and record what each
one does when run WITHOUT `.LEXE`. This script packages every one of those
programs as a `.lexe`, installs it, runs it under the runtime, and compares.

    source -> binary -> DIRECT EXECUTION -> recorded baseline      (Role C)
                     -> .lexe -> install -> lexe run -> compared   (this file)

The point of the split is ATTRIBUTION. When a program misbehaves under `.LEXE`,
the recorded baseline proves the program itself was fine, so the finding lands
on the runtime instead of on the fixture.

--------------------------------------------------------------------------------
THE ORACLE LINE -- what counts as "same behaviour"
--------------------------------------------------------------------------------

Some divergence between direct execution and execution under `.LEXE` is correct
and intended: the runtime sandboxes the program, clears its environment, gives
it a private HOME and a defined working directory, and installs its payload at a
path the program has never seen. An oracle demanding byte-identical output would
report all of that as failure. An oracle forgiving everything would find nothing.

The line drawn here:

  DEMANDED, always (a difference is a finding):
    * the exit status. A non-zero exit that the baseline recorded is the
      program's DECLARED outcome and must be reproduced exactly; so must death
      by signal.
    * every deterministic oracle line -- key AND value -- byte for byte.
    * the SET of keys emitted, including the `OBS_` ones. An `OBS_` value is
      environment-dependent, but whether the program got far enough to print it
      is not.
    * the presence or absence of a `RESULT` line, and its value.
    * the program's own self-check: `RESULT=FAIL` is always a finding, because
      the program is telling us its environment did not behave as it requires.
    * that the oracle stream REACHES THE CALLER. A launch that runs the program
      correctly but loses its output has not run it correctly.
    * that EACH stream the baseline saw bytes on still carries bytes. This is
      checked separately from the oracle comparison and at a coarser grain -- was
      there output at all, not was it identical -- because a specimen whose
      oracle goes to stdout can have its stderr silently discarded and every
      oracle line still match. That happened here, and only this check found it.

  FORGIVEN, unconditionally, with the reason:
    * the VALUE of any `OBS_` key. That is the corpus's own contract
      (tests/workloads/specs/oracle.h): pids, paths, ports, durations and
      kernel details are observations, not assertions.
    * the VALUE of `FIXTURE_ID`. Several specimens read it from the environment,
      and `.LEXE` clears the environment by design (docs/ISOLATION.md,
      "Environment policy"). The KEY is still required: losing the first line
      would mean the program never started.

  FORGIVEN, per specimen, only with a written citation:
    * everything in `against_lexe_expected.json`. Each entry names the specimen,
      the key, the value seen under `.LEXE`, and the clause of
      docs/FORMAT-0.1.md or docs/REFERENCE-POLICY.md or docs/ISOLATION.md that
      makes the divergence intended. An entry with no citation is not accepted
      by this script.

  ANYTHING ELSE is reported as an UNCLASSIFIED divergence, which is the whole
  output of interest. The expectations file is filled in AFTER a measuring run,
  never before: attribute what was measured, do not predict it.

--------------------------------------------------------------------------------
WHAT THE PACKAGING DOES, AND WHY EACH CHOICE IS FAITHFUL
--------------------------------------------------------------------------------

* `stage: plain`          -> payload/bin/<id>
* `stage: helper`         -> payload/bin/<id> + payload/bin/helper_child
* `stage: dlopen`         -> payload/bin/<id> + payload/lib/<the plugin>
* `stage: ldpath`         -> payload/bin/<id> + payload/lib/*.so
* `stage: rpath|runpath|origin` -> the specimen's whole staged tree under payload/
* PE `stage: tree`        -> the six process-tree executables under payload/bin/
* PE `stage: bundle_wlib` -> the exe + wlib.dll + wlib32.dll under payload/bin/
* PE `stage: bundle_cxx_dlls` -> the exe + the three host C++ runtime DLLs the
                             corpus recorded, under payload/bin/
* PE `stage: isolate_exe` -> the exe ALONE, which is that specimen's property

The PE bundle stages reproduce `generate_pe.py`'s `stage_run_dir` deliberately
rather than copying a directory: every PE specimen is compiled into the corpus's
SHARED `bin/`, so "ship the binary's directory" would ship all 72 executables and
none of the DLLs. Getting that wrong produced five confident "the runtime cannot
find a bundled DLL" findings that belonged entirely to this harness.

`{LIBDIR}` and `{HELPER}` in a specimen's argv are placeholders the corpus
substitutes at run time. They are substituted here with the INSTALLED payload's
absolute paths, which is the faithful translation: the specimen is being told
where its own files are, exactly as the direct-execution baseline told it.

Nothing about a specimen is changed to make it pass. If a specimen cannot be
packaged or cannot be run, it is BLOCKED and says why -- never counted as
coverage.

--------------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------------

    python3 against_lexe.py --corpus elf  [--index /tmp/lexe-workloads/index.json]
    python3 against_lexe.py --corpus pe   [--index /tmp/lexe-workloads-pe/index.json]

      --lexe PATH     the runtime under test        (default build-linux/lexe)
      --out DIR       scratch root                  (default /tmp/lexe-vs-workloads[-pe])
      --only A,B      restrict to these fixture ids
      --family F      restrict to a family
      --jobs N        parallel workers (each gets its own LEXE_HOME)
      --chain C       PE only: execution chain to demand (wine | proton)
      --layer L       PE only: which recorded layer baseline to compare against
                      (wine | proton-wine | native; default wine)
      --write-expectations  regenerate a SKELETON expectations file from the
                      divergences just measured, for a human to write reasons
                      into. It is never written with reasons invented.
      --audit-baselines  do not test `.LEXE` at all: re-run the specimens
                      DIRECTLY and check the corpus's recorded baselines. A
                      baseline nobody re-derived is an assumption, and every
                      finding here rests on one. Works for both corpora: the ELF
                      side re-runs the binaries, the PE side replays the `wine`
                      cells against the corpus's own prefix (reusing the prefix
                      is what auditing means; creating one is what the generator
                      does).
      --allow-corpus-drift  run even though the generator on disk differs from
                      the one that produced this corpus (then say so).

    The deliberate SECOND PASSES. Each one changes exactly one thing, so that a
    divergence in the default pass can be attributed to that thing instead of
    argued about. Each is a separate run with its own --out:

      --grant-network add the `network` permission. The five sockets specimens
                      go from one failure to five passes, which is what makes
                      "the resolver failed because /etc/hosts is withheld" a
                      measurement rather than a story.
      --launch-mode M override launch.mode for every specimen. `service` is the
                      one that matters: the orphan/daemon/process-tree specimens
                      lose their background work under `console` and keep it
                      under `service`.
      --extra-settle S wait S more seconds before looking at what a launch left
                      behind. Required with `service`, which returns before the
                      application has finished -- without it the harness reports
                      "nothing was written" for "nothing was written yet".
      --stage-into-data also place a specimen's staged files in the app's data
                      root, which is where the runtime puts the working
                      directory. Turns the cwd specimens from a failure into a
                      pass, isolating the cause to the working directory.

    A GUI specimen (one whose property is that a window reaches a SCREEN) is
    BLOCKED unless DISPLAY is set, because its baseline was recorded on the
    project's namespaced X server and judging it headless would report "no
    window" as a runtime defect. Run it as:

      source scripts/lib/private-display.sh
      pd_run 99 -- env DISPLAY=:99 python3 tests/workloads/against_lexe.py \
             --corpus pe --chain wine --only pe-gui-window --jobs 1

Exit status: 0 when every executed specimen either matched or diverged only in
a classified way; 1 when any specimen FAILED; 2 on a harness/usage error.
BLOCKED specimens never make the run pass and never make it fail -- they are
reported separately and counted separately, because an unexecuted specimen is
not evidence in either direction.

--------------------------------------------------------------------------------
EVIDENCE PROVENANCE -- why this lane fingerprints its own inputs
--------------------------------------------------------------------------------

`source_fingerprint()` in scripts/test.sh deliberately PRUNES `tests/workloads/`,
on the stated grounds that no lane compiles or runs the specimens -- with the
revisit condition written into the comment: "When a workload LANE exists, its
inputs stop being inert and belong back in here."

This file IS that lane, so that condition is now met, and leaving it unaddressed
would be a hole in exactly the guard that exists to stop a green run being
trusted beyond what it earned. Two things are done about it:

  1. This harness fingerprints its own inputs, and does it more precisely than an
     mtime sweep could. The corpus `index.json` records the sha256 of the
     generator that produced it, of every specimen SOURCE file, and of every
     specimen BINARY. `check_corpus_provenance()` re-hashes the generator on disk
     and refuses to run when it differs from the one the corpus was built with;
     every specimen's binary is re-hashed before it is packaged, and a specimen
     whose bytes have moved is BLOCKED rather than compared. `results.json`
     carries all of it. A run of this lane is therefore attributable to an exact
     corpus even though scripts/test.sh cannot see it.

  2. What this file CANNOT do for itself: the harness sources
     (against_lexe.py, against_lexe.sh, against_lexe_expected_*.json) also live
     under the pruned path, and a lane cannot honestly fingerprint itself. When
     this lane is wired into scripts/test.sh, `tests/workloads/` must stop being
     pruned -- or the prune must be narrowed to `tests/workloads/specs*/` only,
     with the generators and this harness covered. That is a one-line change to
     `source_fingerprint()` and it belongs to whoever wires the lane in; it is
     recorded here so it cannot be forgotten, because until it happens a
     scripts/test.sh run that includes this lane is fingerprinting less than it
     appears to.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STDIN_4K = bytes(((i * 37 + 11) & 0xFF) for i in range(4096))

# --------------------------------------------------------------------------- #
#                            result vocabulary                                #
# --------------------------------------------------------------------------- #

PASS, FAIL, BLOCKED = "PASS", "FAIL", "BLOCKED"


class Div:
    """One divergence between the baseline and the run under .LEXE."""

    def __init__(self, kind, key, expected, actual):
        self.kind = kind          # exit | signal | line | key-missing | key-extra
        self.key = key            # oracle key, or a pseudo-key like "<exit>"
        self.expected = expected
        self.actual = actual
        self.reason = None        # filled from the expectations file
        self.citation = None

    @property
    def classified(self):
        return self.reason is not None

    def token(self):
        return f"{self.kind}:{self.key}"

    def as_dict(self):
        return {
            "kind": self.kind, "key": self.key,
            "expected": self.expected, "actual": self.actual,
            "classified": self.classified,
            "reason": self.reason, "citation": self.citation,
        }


# --------------------------------------------------------------------------- #
#                              expectations                                   #
# --------------------------------------------------------------------------- #

def load_expectations(path):
    """{fixture_id: {token: {"reason":..., "citation":...}}}, plus global rules."""
    if not os.path.exists(path):
        return {}, {}
    doc = json.load(open(path))
    per = {}
    for fid, entries in doc.get("specimens", {}).items():
        per[fid] = {}
        for e in entries:
            if not e.get("reason") or not e.get("citation"):
                die(f"expectations: {fid} / {e.get('token')} has no reason or no "
                    f"citation. A forgiven divergence without a written reason is "
                    f"a blind spot, so this file refuses to load.")
            per[fid][e["token"]] = e
    return per, doc.get("families", {})


def apply_expectations(fid, family, divs, per, fam):
    table = dict(fam.get(family, {}))
    for tok, e in per.get(fid, {}).items():
        table[tok] = e
    for d in divs:
        e = table.get(d.token())
        if e is None:
            continue
        # A classification may pin the value it forgives, so that a DIFFERENT
        # value under the same key is still a finding.
        if "actual" in e and e["actual"] != d.actual:
            continue
        d.reason, d.citation = e["reason"], e["citation"]


# --------------------------------------------------------------------------- #
#                               small helpers                                 #
# --------------------------------------------------------------------------- #

def die(msg):
    sys.stderr.write(f"against_lexe: {msg}\n")
    sys.exit(2)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def check_corpus_provenance(index, corpus, allow_drift):
    """Re-derive the corpus's own identity. Returns a provenance record.

    The generator is committed; its output is not. So "which corpus is this?" is
    answered by hashing the generator that made it and comparing with what the
    index recorded -- not by trusting a directory to still hold what it held.
    """
    gen = index.get("generator") or {}
    name = gen.get("file") or ("generate.py" if corpus == "elf" else "generate_pe.py")
    on_disk = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    prov = {"generator": name, "recorded_sha256": gen.get("sha256"),
            "generated_at": index.get("generated_at"), "on_disk_sha256": None,
            "matches": None}
    if os.path.exists(on_disk):
        prov["on_disk_sha256"] = sha256_file(on_disk)
        prov["matches"] = prov["on_disk_sha256"] == prov["recorded_sha256"]
    if prov["matches"] is False and not allow_drift:
        die(f"corpus drift: {name} on disk hashes {prov['on_disk_sha256'][:12]} but "
            f"the corpus at hand was generated by {str(prov['recorded_sha256'])[:12]}.\n"
            f"  The comparison would attribute a fixture change to the runtime.\n"
            f"  Regenerate the corpus, or pass --allow-corpus-drift and say so in "
            f"the report.")
    return prov


def app_id_for(fid):
    """A valid 0.1 App ID (FORMAT-0.1 5.2) derived from the fixture id."""
    seg = re.sub(r"[^A-Za-z0-9-]", "-", fid)
    return f"wl.{seg}"


def parse_oracle(text):
    """-> (ordered deterministic lines, {key: final value}, {obs key: value})."""
    det, vals, obs = [], {}, {}
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        if not re.fullmatch(r"[A-Za-z0-9_]+", key):
            continue
        if key.startswith("OBS_"):
            # The corpus records observations WITHOUT the OBS_ prefix
            # (baseline.runs[].observations), so key the same way it does.
            obs[key[4:]] = val
        else:
            det.append(line)
            vals[key] = val
    return det, vals, obs


def det_map(lines):
    """Final value per key, the way the corpus reports a repeated key."""
    out = {}
    for line in lines:
        k, _, v = line.partition("=")
        out[k] = v
    return out


# --------------------------------------------------------------------------- #
#                                packaging                                    #
# --------------------------------------------------------------------------- #

class Packager:
    def __init__(self, lexe, corpus_root, workroot, corpus, index=None):
        self.lexe = lexe
        self.corpus_root = corpus_root
        self.workroot = workroot
        self.corpus = corpus                       # "elf" | "pe"
        # Where the corpus found the host's C++ runtime DLLs. Recorded by the
        # generator, because they are not in the corpus tree.
        self.cxx_runtime_dlls = (
            ((index or {}).get("support_binaries") or {}).get("cxx_runtime_dlls") or {})

    # ---- payload layout ---------------------------------------------------- #

    def build_payload(self, spec, payload):
        """Copy the specimen and whatever ships beside it into `payload`.

        Returns (entry_relpath, extra_note) or raises Blocked.
        """
        fid = spec["id"]
        stage = spec["stage"]
        binpath = spec["binary"]["path"]
        if not os.path.exists(binpath):
            raise Blocked(f"specimen binary missing: {binpath} (regenerate the corpus)")
        # The bytes that were baselined, or nothing. A specimen whose binary has
        # moved since its baseline was recorded cannot attribute anything.
        want = spec["binary"].get("sha256")
        if want:
            got = sha256_file(binpath)
            if got != want:
                raise Blocked(
                    f"specimen binary no longer matches its baseline: recorded "
                    f"{want[:12]}, on disk {got[:12]}")
        os.makedirs(os.path.join(payload, "bin"), exist_ok=True)

        if self.corpus == "pe":
            return self._payload_pe(spec, payload, stage, binpath)
        return self._payload_elf(spec, payload, stage, binpath, fid)

    def _payload_elf(self, spec, payload, stage, binpath, fid):
        libdir = os.path.join(self.corpus_root, "lib")
        if stage in ("plain",):
            shutil.copy2(binpath, os.path.join(payload, "bin", fid))
            return f"bin/{fid}", None

        if stage == "helper":
            shutil.copy2(binpath, os.path.join(payload, "bin", fid))
            helper = os.path.join(self.corpus_root, "bin", "helper_child")
            if not os.path.exists(helper):
                raise Blocked("helper_child missing from the corpus")
            shutil.copy2(helper, os.path.join(payload, "bin", "helper_child"))
            return f"bin/{fid}", None

        if stage in ("dlopen", "ldpath"):
            shutil.copy2(binpath, os.path.join(payload, "bin", fid))
            dst = os.path.join(payload, "lib")
            os.makedirs(dst, exist_ok=True)
            if not os.path.isdir(libdir):
                raise Blocked("corpus lib/ missing")
            for so in sorted(os.listdir(libdir)):
                shutil.copy2(os.path.join(libdir, so), os.path.join(dst, so))
            return f"bin/{fid}", None

        if stage in ("rpath", "runpath", "origin"):
            # The specimen's property IS its directory layout. Ship the tree.
            tree = os.path.join(self.corpus_root, "stage", fid)
            if not os.path.isdir(tree):
                raise Blocked(f"staged tree missing: {tree}")
            for sub in sorted(os.listdir(tree)):
                s = os.path.join(tree, sub)
                d = os.path.join(payload, sub)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True, symlinks=True)
                else:
                    shutil.copy2(s, d)
            rel = os.path.relpath(binpath, tree)
            return rel.replace(os.sep, "/"), None

        raise Blocked(f"unhandled ELF stage {stage!r}")

    @staticmethod
    def write_staged_files(root, staged):
        """Files the corpus placed in the specimen's working directory.

        They are written into the PACKAGE, because that is where an application
        that ships an asset would carry it. Whether the program can then reach
        them by a relative path is a separate question about the runtime's
        working directory, and is exactly what the comparison measures.
        """
        for rel, content in (staged or {}).items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            data = content if isinstance(content, bytes) else str(content).encode()
            open(p, "wb").write(data)

    def _payload_pe(self, spec, payload, stage, binpath):
        fid = spec["id"]
        name = os.path.basename(binpath)
        bindir = os.path.join(payload, "bin")
        if stage == "plain":
            shutil.copy2(binpath, os.path.join(bindir, name))
            return f"bin/{name}", None
        if stage == "tree":
            tree = os.path.join(self.corpus_root, "tree")
            if not os.path.isdir(tree):
                raise Blocked("PE process-tree binaries missing")
            for f in sorted(os.listdir(tree)):
                shutil.copy2(os.path.join(tree, f), os.path.join(bindir, f))
            if not os.path.exists(os.path.join(bindir, name)):
                shutil.copy2(binpath, os.path.join(bindir, name))
            return f"bin/{name}", None
        if stage in ("bundle_wlib", "bundle_cxx_dlls", "isolate_exe"):
            # The specimen's property is exactly WHICH DLLs sit beside the
            # executable and which do not, so this must reproduce the generator's
            # own staging (generate_pe.py stage_run_dir) rather than copy a
            # directory. The specimens are all built into the corpus's SHARED
            # bin/, so "copy the binary's directory" ships all 72 executables and
            # none of the DLLs -- which is what this harness did first, and it
            # produced five convincing "DLL not found" findings that were its own.
            shutil.copy2(binpath, os.path.join(bindir, name))
            if stage == "bundle_wlib":
                for lib in ("wlib.dll", "wlib32.dll"):
                    src = os.path.join(self.corpus_root, "dll", lib)
                    if os.path.exists(src):
                        shutil.copy2(src, os.path.join(bindir, lib))
            elif stage == "bundle_cxx_dlls":
                found = ((spec.get("support") or {}).get("cxx_runtime_dlls")
                         or self.cxx_runtime_dlls)
                if not found:
                    raise Blocked("the C++ runtime DLLs this specimen must ship "
                                  "are not recorded in the corpus index")
                for nm, src in sorted(found.items()):
                    if src and os.path.exists(src):
                        shutil.copy2(src, os.path.join(bindir, nm))
                    else:
                        raise Blocked(f"C++ runtime DLL {nm} not found at {src}")
            # isolate_exe: the exe ALONE, which is the property.
            return f"bin/{name}", None
        raise Blocked(f"unhandled PE stage {stage!r}")

    # ---- manifest ---------------------------------------------------------- #

    def manifest(self, spec, entry, argv, pubkey, mode, grant_network, chains):
        m = {
            "lexeVersion": "0.1",
            "id": app_id_for(spec["id"]),
            "name": spec["id"],
            "version": "1.0.0",
            "publisher": {"name": "workload-corpus", "publicKey": pubkey},
            "role": "application",
            "applicationType": "windows" if self.corpus == "pe" else "native",
            "architectures": ["x86_64"],
            "entrypoint": {"executable": entry, "arguments": argv},
            "launch": {"mode": mode, "singleInstance": False},
            "install": {"scope": "user", "mode": "bundled"},
            "permissions": ["network"] if grant_network else [],
        }
        if self.corpus == "pe":
            m["execution"] = {"missionCritical": False, "allowedChains": chains}
        # A 32-bit PE is still declared x86_64 in this corpus's own terms: the
        # format's `architectures` is about the host ISA gate (FORMAT 5.3), and
        # WoW64 runs an i386 PE on an x86_64 host. Recorded rather than hidden.
        return m


class Blocked(Exception):
    pass


# --------------------------------------------------------------------------- #
#                               one specimen                                  #
# --------------------------------------------------------------------------- #

class Runner:
    def __init__(self, args, index, pack, lexe_home, keyfile, pubkey):
        self.a = args
        self.index = index
        self.pack = pack
        self.home = lexe_home
        self.key = keyfile
        self.pub = pubkey

    # A worker runs its specimens one at a time, so this is a safe place to keep
    # "is the specimen in hand one that needs a screen".
    gui = False

    def env(self):
        e = dict(os.environ)
        e["LEXE_HOME"] = self.home
        e.pop("WAYLAND_DISPLAY", None)
        # No display for anything that did not declare one, so nothing can reach
        # the developer's desktop even by mistake (docs/TESTING.md 3). A GUI
        # specimen keeps the DISPLAY it was given -- which the caller is expected
        # to have made private.
        if not self.gui:
            e.pop("DISPLAY", None)
        return e

    def lexe(self, argv, **kw):
        return subprocess.run([self.a.lexe] + argv, env=self.env(),
                              capture_output=True, **kw)

    # ------------------------------------------------------------------ run  #

    def run_specimen(self, spec):
        fid = spec["id"]
        rec = {"id": fid, "family": spec["family"], "property": spec["property"]}
        work = os.path.join(self.a.out, "work", fid)
        shutil.rmtree(work, ignore_errors=True)
        payload = os.path.join(work, "payload")
        os.makedirs(payload, exist_ok=True)
        appid = app_id_for(fid)
        self.gui = bool(spec.get("gui"))

        # A specimen whose property is that a window REACHES A SCREEN cannot be
        # judged without a screen, and its baseline was recorded on the project's
        # own namespaced X server. Running it headless and comparing would report
        # "no window" as a runtime defect. BLOCKED, with the way to run it.
        if spec.get("gui") and not os.environ.get("DISPLAY"):
            rec.update(status=BLOCKED,
                       reason="needs a display; its baseline was recorded on a "
                              "private X server. Run this specimen under "
                              "scripts/lib/private-display.sh (pd_run N -- ...) "
                              "with DISPLAY=:N exported.")
            return rec

        try:
            entry, _ = self.pack.build_payload(spec, payload)
            self.pack.write_staged_files(payload, spec.get("staged_files"))
        except Blocked as b:
            rec.update(status=BLOCKED, reason=str(b))
            return rec

        approot = os.path.join(self.home, "apps", appid, "versions", "1.0.0")
        subst = {
            "LIBDIR": os.path.join(approot, "lib"),
            "HELPER": os.path.join(approot, "bin", "helper_child"),
        }
        argv = [a.format(**subst) if "{" in a else a for a in spec["argv"]]
        rec["argv"] = argv

        mode = self.a.launch_mode or ("gui" if spec.get("gui") else "console")
        chains = [self.a.chain] if self.a.chain else ["wine", "proton"]
        man = self.pack.manifest(spec, entry, argv, self.pub, mode,
                                 self.a.grant_network, chains)
        mpath = os.path.join(work, "lexe.json")
        json.dump(man, open(mpath, "w"), indent=2)

        pkg = os.path.join(work, f"{fid}.lexe")
        p = self.pack_pkg(payload, mpath, pkg)
        if p.returncode != 0:
            rec.update(status=BLOCKED,
                       reason=f"lexe pack failed (exit {p.returncode})",
                       detail=(p.stdout + p.stderr).decode("utf-8", "replace")[:2000])
            return rec

        p = self.lexe(["install", pkg, "--yes", "--trust"])
        if p.returncode != 0:
            # An install refusal is a RESULT, not a blocker: it is the runtime
            # declining a legitimate program, which is exactly the kind of thing
            # this pass exists to surface. It goes through the same
            # classification as any other divergence, so a refusal the FORMAT
            # requires can be attributed and a refusal only this implementation
            # imposes cannot hide among them.
            detail = (p.stdout + p.stderr).decode("utf-8", "replace")[:2000]
            first = detail.strip().split("\n")[0]
            d = Div("install", "<refused>", "installs", first)
            apply_expectations(fid, spec["family"], [d], self.a.expect,
                               self.a.expect_fam)
            rec.update(status=PASS if d.classified else FAIL, phase="install",
                       exit=p.returncode, detail=detail,
                       divergences=[d.as_dict()],
                       classified_divergences=1 if d.classified else 0)
            return rec

        datadir0 = os.path.join(self.home, "data", appid)
        if self.a.stage_into_data and spec.get("staged_files"):
            # A deliberate second dimension, never the default: put the asset
            # where the runtime's working directory actually is, to separate "the
            # program cannot find its asset because the CWD moved" from "the
            # program cannot find its asset for some other reason".
            os.makedirs(datadir0, exist_ok=True)
            self.pack.write_staged_files(datadir0, spec["staged_files"])

        launches = []
        n = int(spec.get("runs", 1) or 1)
        for i in range(n):
            launches.append(self.launch(spec, appid))
        rec["launches"] = launches

        # A detached launch (launch.mode service) returns before the application
        # has finished, so a pass that measures what the application LEFT BEHIND
        # has to wait for it. Without this the harness reports "nothing was
        # written" when the truth is "nothing was written YET", which is not a
        # finding about the runtime at all.
        settle = float(spec.get("settle_s", 0) or 0) + float(self.a.extra_settle or 0)
        if settle:
            time.sleep(settle)
        datadir = os.path.join(self.home, "data", appid)
        rec["data_listing"] = sorted(
            x for x in (os.listdir(datadir) if os.path.isdir(datadir) else [])
            if x != ".lexe-data-owner")
        rec["oracle_files"] = self.collect_oracle_files(datadir)

        self.compare(spec, rec)

        # Leave nothing running and nothing installed: 184 installs in one tree
        # would make every later specimen's isolation claim untestable.
        self.lexe(["remove", appid, "--purge-data", "--yes"])
        shutil.rmtree(work, ignore_errors=True)
        return rec

    def pack_pkg(self, payload, mpath, out):
        return self.lexe(["pack", payload, "--manifest", mpath,
                          "--key", self.key, "-o", out])

    def chain_setup_allowance(self, appid):
        """Seconds to allow for the EXECUTION CHAIN to set itself up, on top of
        the specimen's own timeout.

        `spec.timeout_s` describes how long the PROGRAM runs. It says nothing
        about how long the chain takes to become usable, and for a foreign-OS
        chain that is the dominant cost: the runtime builds a private Wine or
        Proton prefix per APPLICATION, in the application's data root. Measured
        on this host: a cold prefix costs 145-170 s and the resulting prefix is
        1.3 GB (wine) or 645 MB (proton); the same application launches again in
        15-21 s. Two different applications in one LEXE_HOME are BOTH cold, so the
        cost is per-application and not amortised.

        The old allowance was a flat +30 s, which sat just under the cold cost.
        It passed only while the cost happened to be cheap, and when the host got
        busy it turned 33 correct-but-slow launches into "timeouts" -- and cost a
        long detour chasing a regression that did not exist. A timeout margin
        that close to a known cost is not a margin.

        A warm application needs none of this, so the allowance is charged only
        when the prefix is not already there.
        """
        if self.a.corpus != "pe" and not self.a.chain:
            return 30.0
        datadir = os.path.join(self.home, "data", appid)
        warm = any(os.path.isdir(os.path.join(datadir, d))
                   for d in (".wine", ".proton"))
        return 30.0 if warm else float(self.a.chain_setup_s)

    def launch(self, spec, appid):
        argv = ["run", appid]
        if self.a.chain:
            argv += ["--chain", self.a.chain]
        stdin = STDIN_4K if spec["stdin"]["bytes"] == 4096 else b""
        if spec["stdin"]["bytes"] not in (0, 4096):
            raise Blocked("unexpected stdin size; the harness only knows STDIN_4K")
        datadir = os.path.join(self.home, "data", appid)
        prefix_warm = any(os.path.isdir(os.path.join(datadir, d))
                          for d in (".wine", ".proton"))
        allowance = self.chain_setup_allowance(appid)
        timeout = float(spec.get("timeout_s", 60) or 60) + allowance
        errdir = os.path.join(self.home, "state", "errors", appid)
        before = set(os.listdir(errdir)) if os.path.isdir(errdir) else set()
        t0 = time.time()
        timed_out = False
        try:
            p = subprocess.run([self.a.lexe] + argv, env=self.env(),
                               input=stdin, capture_output=True, timeout=timeout)
            code, out, err = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            timed_out = True
            code, out, err = None, e.stdout or b"", e.stderr or b""
        dur = round((time.time() - t0) * 1000, 1)

        captured = {}
        if os.path.isdir(errdir):
            new = sorted(set(os.listdir(errdir)) - before)
            for f in new:
                if f.endswith((".stdout", ".stderr")):
                    captured[f] = open(os.path.join(errdir, f), "rb").read()

        return {
            "exit": code, "timed_out": timed_out, "duration_ms": dur,
            "stdout": out, "stderr": err, "captured": captured,
            # Recorded so a slow FIRST launch can never again be mistaken for a
            # hang. A timeout with prefix_warm false and a duration near the
            # allowance is chain setup being slow; a timeout with prefix_warm
            # true is the program.
            "prefix_warm": prefix_warm, "timeout_s": timeout,
            "chain_setup_allowance_s": allowance,
        }

    def collect_oracle_files(self, datadir):
        out = {}
        if not os.path.isdir(datadir):
            return out
        for root, _, files in os.walk(datadir):
            for f in files:
                if f.endswith(".oracle"):
                    p = os.path.join(root, f)
                    out[os.path.relpath(p, datadir)] = open(
                        p, "rb").read().decode("utf-8", "replace")
        return out

    # -------------------------------------------------------------- compare  #

    def baseline_for(self, spec):
        if self.a.corpus == "elf":
            runs = spec["baseline"]["runs"]
            return runs[-1], spec["baseline"]
        layer = self.a.layer
        b = spec["baselines"].get(layer)
        if not b or not b["repeats"]:
            raise Blocked(f"no {layer} baseline recorded for this specimen")
        r = b["repeats"][0]
        return r["launches"][-1], r

    def oracle_text(self, spec, launch, rec, base_launch=None):
        """The stream the specimen's oracle went to, as it REACHED us.

        Three sources, in the order they establish different facts:
          1. the stream itself, passed through to the caller -- what a caller
             actually sees;
          2. the runtime's own capture under state/errors/, which is where a
             non-zero-exit launch's output goes instead of to the caller;
          3. for the PE corpus, the specimen's .oracle FILE, which is the
             corpus's primary artifact by design.
        Whichever is used is recorded, because "the output only exists in an
        error report" is itself a finding.
        """
        if self.a.corpus == "pe":
            # The PE corpus writes every oracle line to a FILE as well as to the
            # stream, and says the file is the primary comparison artifact -- it
            # exists because one of the layers delivers no stdio at all. Use it,
            # and let the separate per-stream delivery checks carry the question
            # of whether the streams also arrived.
            #
            # Exactly ONE file, the one the baseline launch names. A process-tree
            # specimen leaves one oracle file per NODE (t_launcher, t_main,
            # t_helper, ...), and concatenating them compares a whole tree's
            # output against one node's baseline -- which is how this harness
            # first "found" fifty divergences that were entirely its own.
            # Match by NAME where possible, but fall back to "the only file there
            # is". A specimen's oracle file is named after FIXTURE_ID, which comes
            # from the environment -- and the runtime clears the environment, so
            # under `.LEXE` the same specimen writes `pe-io-streams.oracle` where
            # its baseline wrote `pe-io-both-streams.oracle`. Insisting on the name
            # made the harness silently fall back to the STREAM and then report
            # every stderr line as missing, which is a fact about the file name and
            # not about the runtime.
            want_file = (base_launch or {}).get("oracle_file")
            files = rec["oracle_files"]
            if want_file:
                for name, body in files.items():
                    if os.path.basename(name) == want_file:
                        return body, "oracle-file"
            if len(files) == 1:
                return next(iter(files.values())), "oracle-file(single)"
            if files:
                return "\n".join(files.values()), "oracle-file(merged)"
            if launch["stdout"] or launch["stderr"]:
                return ((launch["stdout"] or b"") + (launch["stderr"] or b"")
                        ).decode("utf-8", "replace"), "stream"
            for name, data in sorted(launch["captured"].items()):
                if data:
                    return data.decode("utf-8", "replace"), "error-report-capture"
            return "", "absent"

        want = spec["declared"]["oracle_stream"]
        streamed = launch["stdout"] if want == "stdout" else launch["stderr"]
        if streamed:
            return streamed.decode("utf-8", "replace"), "stream"
        for name, data in sorted(launch["captured"].items()):
            if name.endswith("." + ("stdout" if want == "stdout" else "stderr")) and data:
                return data.decode("utf-8", "replace"), "error-report-capture"
        if rec["oracle_files"]:
            return "\n".join(rec["oracle_files"].values()), "oracle-file"
        return "", "absent"

    def compare(self, spec, rec):
        try:
            base_launch, base_all = self.baseline_for(spec)
        except Blocked as b:
            rec.update(status=BLOCKED, reason=str(b))
            return
        launch = rec["launches"][-1]
        divs = []

        # ---- exit status ---------------------------------------------------- #
        if self.a.corpus == "elf":
            bexit, bsig = base_launch["exit_code"], base_launch.get("signal")
        else:
            bexit, bsig = base_launch["exit_code"], None
        if launch["timed_out"]:
            # Say WHICH kind of timeout. A cold-prefix timeout is the chain
            # setting itself up too slowly for the allowance; a warm one is the
            # program. Conflating them cost a long detour chasing a regression
            # that did not exist, so the two are never reported the same way
            # again.
            if launch.get("prefix_warm") is False and self.a.corpus == "pe":
                what = (f"TIMED OUT after {launch['timeout_s']:.0f}s with a COLD "
                        f"per-application prefix -- chain setup, not the program")
            else:
                what = f"TIMED OUT after {launch['timeout_s']:.0f}s"
            divs.append(Div("exit", "<exit>", f"exit={bexit} signal={bsig}", what))
        else:
            got = launch["exit"]
            if bsig is not None:
                # Direct execution died of a signal. A launcher cannot re-raise
                # it; what it MUST do is not report success. 128+n is the shell
                # convention and is accepted; anything else, including 0, is a
                # divergence.
                if got not in (128 + bsig, -bsig, bsig):
                    divs.append(Div("signal", "<signal>",
                                    f"killed by signal {bsig} "
                                    f"({base_launch.get('signal_name')})",
                                    f"exit={got}"))
            elif got != bexit:
                divs.append(Div("exit", "<exit>", str(bexit), str(got)))

        # ---- the oracle stream --------------------------------------------- #
        text, source = self.oracle_text(spec, launch, rec, base_launch)
        rec["oracle_source"] = source
        if self.a.corpus == "elf" and source != "stream" and text:
            divs.append(Div("line", "<stream-delivery>",
                            "the oracle stream reaches the caller",
                            f"only via {source}"))
        # ---- per-stream delivery, independent of the oracle ----------------- #
        # Coarse on purpose: did anything at all arrive on a stream the baseline
        # had bytes on. A specimen whose oracle is on stdout can lose its whole
        # stderr with every compared line still matching.
        for name, bkey in (("stdout", "stdout_bytes"), ("stderr", "stderr_bytes")):
            had = (base_launch.get(bkey) or 0) > 0
            got = len(launch[name] or b"")
            if had and got == 0:
                via = [f for f in launch["captured"] if f.endswith("." + name)]
                divs.append(Div("line", f"<{name}-delivery>",
                                f"{base_launch[bkey]} bytes reached the caller",
                                "0 bytes" + (f" (only in {via[0]})" if via else "")))

        # ---- stdout INTEGRITY, where stdout is pure data -------------------- #
        # For a specimen whose oracle goes to stderr, stdout carries nothing but
        # the payload it was written to carry, so the baseline's byte count and
        # digest are exactly comparable. This is the check that caught stdout
        # being relayed as a NUL-terminated string.
        pure_data = (spec["declared"].get("oracle_stream") == "stderr"
                     or spec["declared"].get("bulk_check"))
        if pure_data and self.a.corpus == "elf":
            want_n = base_launch.get("stdout_bytes") or 0
            got = launch["stdout"] or b""
            if want_n and len(got) != want_n:
                divs.append(Div("line", "<stdout-integrity>",
                                f"{want_n} bytes",
                                f"{len(got)} bytes ({want_n - len(got)} lost)"))
            elif want_n and base_launch.get("stdout_sha256"):
                if hashlib.sha256(got).hexdigest() != base_launch["stdout_sha256"]:
                    divs.append(Div("line", "<stdout-integrity>",
                                    f"sha256 {base_launch['stdout_sha256'][:16]}",
                                    "different bytes, same length"))

        det, vals, obs = parse_oracle(text)
        rec["oracle_lines"] = det
        rec["obs_keys"] = sorted(obs)

        bdet = base_launch["oracle_deterministic_lines"]
        bvals = det_map(bdet)
        bobs = base_launch.get("observations", {})

        for k in sorted(set(bvals) | set(vals)):
            if k not in vals:
                divs.append(Div("key-missing", k, bvals[k], None))
            elif k not in bvals:
                divs.append(Div("key-extra", k, None, vals[k]))
            elif vals[k] != bvals[k]:
                if k == "FIXTURE_ID":
                    continue          # forgiven: value comes from the environment
                divs.append(Div("line", k, bvals[k], vals[k]))

        for k in sorted(set(bobs) | set(obs)):
            if k not in obs:
                divs.append(Div("key-missing", "OBS_" + k, bobs[k], None))
            elif k not in bobs:
                divs.append(Div("key-extra", "OBS_" + k, None, obs[k]))
            # values deliberately not compared -- the corpus's own contract

        # ---- the specimen's own verdict ------------------------------------ #
        if vals.get("RESULT") == "FAIL":
            rec["self_check_failed"] = [k for k, v in vals.items()
                                        if v == "no" and k != "RESULT"]

        # ---- filesystem effects -------------------------------------------- #
        want_files = spec["declared"].get("post_files") or {}
        for name in sorted(want_files):
            base = os.path.basename(name)
            if base not in rec["data_listing"] and base not in rec["oracle_files"]:
                divs.append(Div("key-missing", f"<post-file:{base}>",
                                "present after the launch", "absent"))

        apply_expectations(spec["id"], spec["family"], divs,
                           self.a.expect, self.a.expect_fam)
        rec["divergences"] = [d.as_dict() for d in divs]
        unclassified = [d for d in divs if not d.classified]
        rec["status"] = FAIL if unclassified else PASS
        rec["classified_divergences"] = len(divs) - len(unclassified)
        # One defect affects a whole class of specimens at once (a non-zero exit
        # makes the runtime withhold the program's output). Counting it 40 times
        # in a flat FAIL list would bury every other finding, so it is tagged and
        # reported as one group -- without being downgraded, because it IS a
        # defect and the specimens really did diverge.
        toks = {d.token() for d in unclassified}
        delivery = {"line:<stream-delivery>", "line:<stdout-delivery>",
                    "line:<stderr-delivery>"}
        if toks and toks <= delivery:
            rec["sole_divergence"] = "stream-delivery"
            rec["delivery_tokens"] = sorted(toks)


# --------------------------------------------------------------------------- #
#                      auditing the fixtures themselves                       #
# --------------------------------------------------------------------------- #

def audit_baselines(a, index, corpus_root, specs):
    """Re-run specimens WITHOUT .LEXE and check the recorded baseline.

    A baseline nobody re-derived is an assumption, and every `.LEXE` defect this
    harness reports rests on one. This mode reproduces the direct execution the
    corpus says it performed -- same argv, same environment, same working
    directory, same stdin -- and compares the deterministic oracle and the exit
    status against what the index recorded. It exists so that a runtime defect
    cannot turn out to have been a fixture defect.

    The PE corpus is audited by `audit_pe_baselines` below, which reuses the
    corpus's OWN Wine prefix: re-creating the prefix would be re-running the
    generator rather than auditing it.
    """
    # The generator runs every specimen in a REPLACED environment, not an
    # inherited one, and records only the keys it added (`env_extra`). Auditing
    # with os.environ instead reproduces a different run -- which this audit
    # discovered the hard way, by "finding" a PATH mismatch that was its own.
    BASE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "TERM": "dumb", "SHELL": "/bin/sh"}
    scratch = os.path.join(a.out, "baseline-audit")
    shutil.rmtree(scratch, ignore_errors=True)
    os.makedirs(scratch, exist_ok=True)

    bad, ok, skipped = [], 0, []
    for s in specs:
        binpath = s["binary"]["path"]
        base = s["baseline"]["runs"][-1]
        old = s["baseline"]["run_dir"]
        if not os.path.exists(binpath):
            skipped.append((s["id"], "specimen binary absent"))
            continue
        # A FRESH working directory, not the corpus's retained one. Several
        # specimens' declared property is state that accumulates in the working
        # directory, so re-running inside the kept directory continues the
        # baseline instead of reproducing it.
        rundir = os.path.join(scratch, s["id"])
        os.makedirs(rundir, exist_ok=True)
        Packager.write_staged_files(rundir, s.get("staged_files"))
        env = dict(BASE_ENV)
        for k, v in (base.get("env_extra") or {}).items():
            env[k] = v.replace(old, rundir) if isinstance(v, str) else v
        for d in ("home", "tmp", "xdg/data", "xdg/config", "xdg/cache"):
            os.makedirs(os.path.join(rundir, *d.split("/")), exist_ok=True)
        stdin = STDIN_4K if s["stdin"]["bytes"] == 4096 else b""
        nruns = int(s.get("runs", 1) or 1)
        try:
            for _ in range(nruns):
                p = subprocess.run(base["argv"], cwd=rundir, env=env, input=stdin,
                                   capture_output=True,
                                   timeout=float(s.get("timeout_s", 60) or 60) + 30)
            code = p.returncode
            out, err = p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            bad.append((s["id"], "timed out on re-run; the baseline recorded "
                                 f"exit {base['exit_code']}"))
            continue
        sig = -code if code is not None and code < 0 else None
        want_sig = base.get("signal")
        problems = []
        if want_sig is not None:
            if sig != want_sig:
                problems.append(f"signal {want_sig} recorded, got "
                                f"{'signal ' + str(sig) if sig else 'exit ' + str(code)}")
        elif code != base["exit_code"]:
            problems.append(f"exit {base['exit_code']} recorded, got {code}")
        want = s["declared"]["oracle_stream"]
        text = (out if want == "stdout" else err).decode("utf-8", "replace")
        det, _, _ = parse_oracle(text)
        if det != base["oracle_deterministic_lines"]:
            exp, got = det_map(base["oracle_deterministic_lines"]), det_map(det)
            for k in sorted(set(exp) | set(got)):
                if exp.get(k) != got.get(k):
                    problems.append(f"{k}: recorded {exp.get(k)!r}, got {got.get(k)!r}")
        if problems:
            bad.append((s["id"], "; ".join(problems[:6])))
        else:
            ok += 1
    w = sys.stdout.write
    w("\n  BASELINE AUDIT -- re-running specimens WITHOUT .LEXE\n\n")
    for fid, why in skipped:
        w(f"  SKIP    {fid}: {why}\n")
    for fid, why in bad:
        w(f"  FAIL    {fid}: {why}\n")
    w(f"\n  re-derived {ok + len(bad)} baselines: {ok} reproduced, "
      f"{len(bad)} did NOT, {len(skipped)} skipped\n\n")
    return 1 if bad else 0


def audit_pe_baselines(a, index, corpus_root, specs):
    """Re-derive the PE corpus's `wine` baselines, without `.LEXE`.

    Same purpose as audit_baselines: every PE finding this harness reports rests
    on a recorded baseline, and a baseline nobody re-derived is an assumption. It
    replays each specimen the way generate_pe.py did -- the recorded command, the
    reconstructed layer environment, the same staging of DLLs beside the
    executable, a FRESH working directory -- and compares the resulting `.oracle`
    FILE and exit code against what the index recorded.

    It reuses the corpus's own Wine prefix rather than making one. Creating a
    prefix is what the generator does; reusing it is what auditing the generator
    means. The `wine` layer only: `proton-wine` would need Proton's prefix on top,
    and `native` is an ordinary ELF already covered by the ELF audit.

    A specimen whose property is a window on a screen is SKIPPED, not failed --
    its baseline was recorded on a private X server and this mode brings no
    display.
    """
    OUT = corpus_root
    # generate_pe.py's own BASE_ENV. Note it sets a UTF-8 locale: that is why the
    # recorded baselines have intact UTF-8, and why a runtime that supplies no
    # usable locale diverges from them.
    BASE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "HOME": os.path.expanduser("~")}
    CXX_DLLS = ["libstdc++-6.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll"]
    cxx_found = ((index.get("support_binaries") or {}).get("cxx_runtime_dlls") or {})
    prefix = os.path.join(OUT, "prefix-wine")
    if not os.path.isdir(prefix):
        die(f"the corpus's wine prefix is missing ({prefix}); regenerate the "
            f"corpus with generate_pe.py")
    if not shutil.which("wine"):
        die("wine is not installed, so the wine baselines cannot be re-derived")

    scratch = os.path.join(a.out, "pe-baseline-audit")
    shutil.rmtree(scratch, ignore_errors=True)
    os.makedirs(scratch, exist_ok=True)

    ok, bad, skipped, problems = 0, 0, 0, []
    for s in specs:
        fid = s["id"]
        b = (s.get("baselines") or {}).get("wine")
        if not b or not b.get("repeats"):
            skipped += 1
            problems.append((fid, "SKIP", "no wine baseline recorded"))
            continue
        if s.get("gui"):
            skipped += 1
            problems.append((fid, "SKIP", "its property is a window on a screen; "
                                          "this mode brings no display"))
            continue
        rep = b["repeats"][0]
        rundir = os.path.join(scratch, fid)
        os.makedirs(rundir, exist_ok=True)
        Packager.write_staged_files(rundir, s.get("staged_files"))

        # Reproduce generate_pe.py's stage_run_dir: WHICH DLLs sit beside the
        # executable is several specimens' whole property.
        exe = s["build"]["target"]
        stage = s["stage"]
        if stage in ("bundle_wlib", "isolate_exe", "bundle_cxx_dlls"):
            shutil.copy2(exe, rundir)
            if stage == "bundle_wlib":
                for lib in ("wlib.dll", "wlib32.dll"):
                    src = os.path.join(OUT, "dll", lib)
                    if os.path.exists(src):
                        shutil.copy2(src, rundir)
            elif stage == "bundle_cxx_dlls":
                for nm in CXX_DLLS:
                    src = cxx_found.get(nm)
                    if src and os.path.exists(src):
                        shutil.copy2(src, rundir)
            exe = os.path.join(rundir, os.path.basename(exe))

        env = dict(BASE_ENV)
        env["FIXTURE_ID"] = fid
        env["WINEDEBUG"] = "-all"
        env["WINEDLLOVERRIDES"] = "mscoree,mshtml="
        env["WINEPREFIX"] = prefix
        env.update(s.get("env") or {})
        stdin = STDIN_4K if s["stdin"]["bytes"] == 4096 else b""

        last = None
        try:
            for _ in range(len(rep["launches"])):
                last = subprocess.run(["wine", exe] + s["argv"], cwd=rundir, env=env,
                                      input=stdin, capture_output=True,
                                      timeout=float(s.get("timeout_s", 120) or 120) + 60)
        except subprocess.TimeoutExpired:
            bad += 1
            problems.append((fid, "FAIL", "timed out on re-run; the baseline "
                                          f"recorded exit "
                                          f"{rep['launches'][-1]['exit_code']}"))
            continue

        recorded = rep["launches"][-1]
        ps = []
        # Honour the instability the corpus DECLARED for this layer; a specimen
        # measured as nondeterministic must not be re-reported as a mismatch.
        allowed = {recorded["exit_code"]}
        allowed.update((s["declared"].get("exit_one_of_by_layer") or {})
                       .get("wine", []) or [])
        if last.returncode not in allowed:
            ps.append(f"exit: recorded {sorted(allowed)}, got {last.returncode}")

        want_file = recorded.get("oracle_file")
        text = ""
        found = [f for f in os.listdir(rundir) if f.endswith(".oracle")]
        if want_file and os.path.exists(os.path.join(rundir, want_file)):
            text = open(os.path.join(rundir, want_file),
                        encoding="utf-8", errors="replace").read()
        elif found:
            text = open(os.path.join(rundir, found[0]),
                        encoding="utf-8", errors="replace").read()
        elif recorded.get("oracle_file_present"):
            ps.append(f"oracle file {want_file} was recorded present, not produced")

        det, vals, _ = parse_oracle(text)
        exp = det_map(recorded["oracle_deterministic_lines"])
        unstable = set(b.get("unstable_lines") or [])
        for k in sorted(set(exp) | set(vals)):
            if exp.get(k) != vals.get(k) and k not in unstable:
                ps.append(f"{k}: recorded {exp.get(k)!r}, got {vals.get(k)!r}")

        if ps:
            bad += 1
            problems.append((fid, "FAIL", "; ".join(ps[:5])))
        else:
            ok += 1

    w = sys.stdout.write
    w("\n  PE BASELINE AUDIT -- re-running the wine cells WITHOUT .LEXE\n\n")
    for fid, kind, why in problems:
        w(f"  {kind:5} {fid}: {why}\n")
    w(f"\n  re-derived {ok + bad} wine baselines: {ok} reproduced, {bad} did NOT, "
      f"{skipped} skipped\n\n")
    return 1 if bad else 0


# --------------------------------------------------------------------------- #
#                                  driver                                     #
# --------------------------------------------------------------------------- #

def select(index, args):
    out = []
    only = set(args.only.split(",")) if args.only else None
    for s in index["specimens"]:
        if s["verdict"]["status"] != "baseline-ok":
            continue
        if only and s["id"] not in only:
            continue
        if args.family and s["family"] != args.family:
            continue
        out.append(s)
    return out


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--corpus", choices=("elf", "pe"), required=True)
    ap.add_argument("--index")
    ap.add_argument("--lexe", default=os.path.join(REPO, "build-linux", "lexe"))
    ap.add_argument("--out")
    ap.add_argument("--only")
    ap.add_argument("--family")
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--chain")
    ap.add_argument("--layer", default="wine",
                    help="PE only: which recorded layer baseline to compare with")
    ap.add_argument("--grant-network", action="store_true")
    ap.add_argument("--launch-mode", choices=("console", "gui", "service"),
                    help="override launch.mode for every specimen in this pass")
    ap.add_argument("--chain-setup-s", type=float, default=420.0,
                    help="seconds allowed for a foreign-OS chain to build its "
                         "per-application prefix, on top of the specimen's own "
                         "timeout, and only when that prefix is not already "
                         "there (measured cold cost on this host: 145-170s)")
    ap.add_argument("--extra-settle", type=float, default=0.0,
                    help="extra seconds to wait after the last launch before "
                         "looking at what it left behind (use with a detached "
                         "launch mode, which returns before the work is done)")
    ap.add_argument("--stage-into-data", action="store_true",
                    help="also place a specimen's staged files in the app's data "
                         "root, which is where the runtime puts the cwd")
    ap.add_argument("--expectations")
    ap.add_argument("--write-expectations", action="store_true")
    ap.add_argument("--audit-baselines", action="store_true",
                    help="re-run the specimens WITHOUT .LEXE and check the "
                         "recorded baselines instead of comparing against them")
    ap.add_argument("--allow-corpus-drift", action="store_true",
                    help="run even though the generator on disk differs from the "
                         "one that produced this corpus (say so in the report)")
    a = ap.parse_args()

    a.index = a.index or (f"/tmp/lexe-workloads/index.json" if a.corpus == "elf"
                          else "/tmp/lexe-workloads-pe/index.json")
    a.out = a.out or (f"/tmp/lexe-vs-workloads" if a.corpus == "elf"
                      else "/tmp/lexe-vs-workloads-pe")
    a.expectations = a.expectations or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        f"against_lexe_expected_{a.corpus}.json")

    if not os.path.exists(a.lexe):
        die(f"runtime not found: {a.lexe} (build it with scripts/build.sh)")
    if not os.path.exists(a.index):
        die(f"corpus index not found: {a.index}\n"
            f"  regenerate: python3 tests/workloads/"
            f"{'generate.py' if a.corpus == 'elf' else 'generate_pe.py'}")

    index = json.load(open(a.index))
    corpus_root = os.path.dirname(os.path.abspath(a.index))
    provenance = check_corpus_provenance(index, a.corpus, a.allow_corpus_drift)
    a.expect, a.expect_fam = load_expectations(a.expectations)

    specs = select(index, a)
    if a.audit_baselines:
        if a.corpus == "pe":
            return audit_pe_baselines(a, index, corpus_root, specs)
        return audit_baselines(a, index, corpus_root, specs)
    total_in_corpus = len(index["specimens"])
    unusable = [s["id"] for s in index["specimens"]
                if s["verdict"]["status"] != "baseline-ok"]

    shutil.rmtree(a.out, ignore_errors=True)
    os.makedirs(os.path.join(a.out, "work"), exist_ok=True)

    # One LEXE_HOME per worker. Parallel installs into one tree would make every
    # specimen's isolation claim depend on every other specimen's timing.
    jobs = max(1, min(a.jobs, len(specs)))
    homes, keys, pubs = [], [], []
    for i in range(jobs):
        h = os.path.join(a.out, f"home{i}")
        os.makedirs(h, exist_ok=True)
        k = os.path.join(a.out, f"key{i}.json")
        env = dict(os.environ, LEXE_HOME=h)
        p = subprocess.run([a.lexe, "keygen", k], env=env, capture_output=True)
        if p.returncode != 0:
            die("lexe keygen failed: " + p.stderr.decode("utf-8", "replace"))
        homes.append(h)
        keys.append(k)
        pubs.append(json.load(open(k))["publicKey"])

    pack = Packager(a.lexe, corpus_root, a.out, a.corpus, index)
    q = queue.Queue()
    for s in specs:
        q.put(s)
    results, lock = [], threading.Lock()

    def worker(i):
        r = Runner(a, index, pack, homes[i], keys[i], pubs[i])
        while True:
            try:
                s = q.get_nowait()
            except queue.Empty:
                return
            try:
                rec = r.run_specimen(s)
            except Exception as exc:                        # harness defect
                rec = {"id": s["id"], "family": s["family"], "status": BLOCKED,
                       "reason": f"harness error: {type(exc).__name__}: {exc}"}
            with lock:
                results.append(rec)
                mark = {PASS: ".", FAIL: "F", BLOCKED: "b"}.get(rec["status"], "?")
                sys.stderr.write(mark)
                sys.stderr.flush()

    ts = [threading.Thread(target=worker, args=(i,), daemon=True)
          for i in range(jobs)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    sys.stderr.write("\n")
    wall = round(time.time() - t0, 1)

    results.sort(key=lambda r: r["id"])
    summary = {
        "corpus": a.corpus, "index": a.index, "layer": a.layer,
        "corpus_provenance": provenance,
        "expectations_file": a.expectations,
        "expectations_sha256": (sha256_file(a.expectations)
                                if os.path.exists(a.expectations) else None),
        "harness_sha256": sha256_file(os.path.abspath(__file__)),
        "chain": a.chain, "grant_network": a.grant_network,
        "launch_mode_override": a.launch_mode,
        "stage_into_data": a.stage_into_data,
        "lexe": a.lexe, "lexe_sha256": sha256_file(a.lexe),
        "wall_seconds": wall,
        "specimens_in_corpus": total_in_corpus,
        "unusable_in_corpus": unusable,
        "executed": len(results),
        "pass": sum(1 for r in results if r["status"] == PASS),
        "fail": sum(1 for r in results if r["status"] == FAIL),
        "blocked": sum(1 for r in results if r["status"] == BLOCKED),
        "fail_stream_delivery_only": sorted(
            r["id"] for r in results if r.get("sole_divergence") == "stream-delivery"),
    }
    out = {"summary": summary, "results": strip_bytes(results)}
    rp = os.path.join(a.out, "results.json")
    json.dump(out, open(rp, "w"), indent=1)

    report(summary, results, rp)
    if a.write_expectations:
        write_skeleton(a, results)
    return 1 if summary["fail"] else 0


def strip_bytes(results):
    """Byte payloads are big and non-JSON; keep sizes and heads."""
    out = []
    for r in results:
        r = dict(r)
        for L in r.get("launches", []) or []:
            for k in ("stdout", "stderr"):
                b = L.get(k, b"")
                L[k + "_bytes"] = len(b)
                L[k + "_head"] = b[:400].decode("utf-8", "replace")
                L.pop(k, None)
            L["captured"] = {k: len(v) for k, v in (L.get("captured") or {}).items()}
        out.append(r)
    return out


def report(summary, results, rp):
    w = sys.stdout.write
    w("\n")
    w(f"  corpus {summary['corpus']}  runtime {os.path.basename(summary['lexe'])}"
      f" ({summary['lexe_sha256'][:12]})  {summary['wall_seconds']}s\n")
    p = summary["corpus_provenance"]
    w(f"  corpus generated {p['generated_at']} by {p['generator']} "
      f"({str(p['recorded_sha256'])[:12]}), generator on disk "
      f"{'MATCHES' if p['matches'] else 'DIFFERS'}\n")
    w(f"  harness {summary['harness_sha256'][:12]}  expectations "
      f"{str(summary['expectations_sha256'])[:12]}\n")
    if summary["chain"]:
        w(f"  chain {summary['chain']}  baseline layer {summary['layer']}\n")
    if summary["grant_network"]:
        w("  the `network` permission was GRANTED for this pass\n")
    w("\n")
    for r in results:
        if r["status"] == PASS and not r.get("divergences"):
            continue
        if r["status"] == PASS:
            w(f"  PASS    {r['id']}  ({r['classified_divergences']} "
              f"classified divergence(s))\n")
            continue
        if r["status"] == BLOCKED:
            w(f"  BLOCKED {r['id']}: {r.get('reason')}\n")
            continue
        if r.get("sole_divergence") == "stream-delivery":
            continue                      # grouped in the summary below
        w(f"  FAIL    {r['id']} -- {r.get('property', '')}\n")
        if r.get("phase") == "install":
            w(f"            install refused (exit {r['exit']}): "
              f"{(r.get('detail') or '').strip().splitlines()[:1]}\n")
        for d in r.get("divergences", []):
            if d["classified"]:
                continue
            w(f"            [{d['kind']}] {d['key']}: baseline "
              f"{d['expected']!r} -> lexe {d['actual']!r}\n")
        if r.get("self_check_failed"):
            w(f"            the program's own checks that failed: "
              f"{', '.join(r['self_check_failed'])}\n")
    sd = summary["fail_stream_delivery_only"]
    if sd:
        w(f"  FAIL x{len(sd)}  one defect, one group: the program ran correctly and\n"
          f"            produced exactly the baseline's oracle, but the runtime did\n"
          f"            NOT deliver it to the caller -- it was recovered only from\n"
          f"            the runtime's own error-report capture.\n")
        for i in range(0, len(sd), 3):
            w("            " + "  ".join(sd[i:i + 3]) + "\n")
    w("\n")
    w(f"  in corpus {summary['specimens_in_corpus']}   "
      f"executed {summary['executed']}   "
      f"PASS {summary['pass']}   FAIL {summary['fail']}   "
      f"BLOCKED {summary['blocked']}\n")
    if summary["unusable_in_corpus"]:
        w(f"  not usable as material (no baseline-ok verdict): "
          f"{', '.join(summary['unusable_in_corpus'])}\n")
    w(f"  full record: {rp}\n\n")


def write_skeleton(a, results):
    """Emit the divergences measured, for a human to attribute. No reasons."""
    doc = {"_note": "Fill in reason + citation for each entry BY HAND. "
                    "against_lexe.py refuses to load an entry without both.",
           "families": {}, "specimens": {}}
    for r in results:
        ent = [{"token": d["kind"] + ":" + d["key"], "actual": d["actual"],
                "baseline": d["expected"], "reason": "", "citation": ""}
               for d in r.get("divergences", []) if not d["classified"]]
        if ent:
            doc["specimens"][r["id"]] = ent
    p = os.path.join(a.out, f"expectations-skeleton-{a.corpus}.json")
    json.dump(doc, open(p, "w"), indent=1)
    sys.stdout.write(f"  expectations skeleton (unattributed): {p}\n\n")


if __name__ == "__main__":
    sys.exit(main())

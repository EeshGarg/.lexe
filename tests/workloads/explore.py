#!/usr/bin/env python3
"""explore.py — high-throughput exploration of .LEXE's externally visible behaviour.

Four engines behind one command, sharing one fixture factory and one rule about
evidence: **nothing here asks .LEXE what it did.** State is read back through the
CLI's public surface and through the behaviour of programs whose correct output
was established by direct execution before .LEXE ever saw them.

    explore.py cost     measure what each operation costs, before sizing anything
    explore.py sample   a deterministic pairwise sampler over ten dimensions
    explore.py model    an independent abstract lifecycle model, run at scale
    explore.py reduce   automatic minimisation of a failing trace
    explore.py race     generated concurrent schedules, forced where possible

Why an independent model at all. A test that imports the runtime's own notion of
state cannot disagree with the runtime; it can only restate it. The model in
`Model` below was written from FORMAT-0.1 §9, docs/ERRORS.md §1 and
docs/CONCURRENCY.md, and it is deliberately allowed to be WRONG: where those
documents do not decide an outcome the model says UNDERSPEC and the engine falls
back to a property that needs no spec at all — that the answer be the SAME every
time the same abstract state is reached, by whatever path. A runtime whose refusal
code depends on how you arrived somewhere has a defect even when no document says
which code is right.

Replay. Every randomised choice descends from --seed. A case id is a digest of the
seed plus the case's own coordinates, and --replay <case-id> re-derives the plan
and executes exactly that case. A sampler whose output cannot be replayed is not
evidence.

Measurement hygiene. $PATH is pinned to a short system PATH for every child (see
PINNED_PATH): on a WSL host the inherited PATH carries ~36 /mnt/c directories, and
.LEXE's compatibility-provider discovery stats each candidate binary in each of
them. That is 734 stats at ~4ms apiece, which turns `lexe doctor` from 22ms into
3.5 SECONDS. Left unpinned it would dominate every number this file reports and
would look like a runtime cost. Measured, not assumed: `explore.py cost` prints
both, with the host load beside them.

Usage (inside WSL; the corpus is Linux-native):
    python3 explore.py cost   --lexe ../../build-linux/lexe
    python3 explore.py sample --lexe ../../build-linux/lexe --seed 1
    python3 explore.py model  --sequences 4000 --seed 1
    python3 explore.py race   --repeats 40
    python3 explore.py reduce --trace failure.json
"""

import argparse
import concurrent.futures as futures
import copy
import fcntl
import hashlib
import itertools
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

# A short, deterministic PATH. See the module docstring: this is a measurement
# decision, not a convenience. It is also the honest one — a Linux host running
# .LEXE for real does not have 36 Windows directories on its PATH, so timing the
# runtime through one measures the host and calls it the runtime.
PINNED_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"

# Every operation measured on this host sits between 6ms and 46ms (`explore.py
# cost`). This timeout is therefore ~1300x the median: it exists to turn a
# deadlock into a FAIL instead of a hung suite, and it must never be sized close
# to a known cost. A margin sized just under a real cost once turned 33 correct
# launches in this project into "timeouts", which is why this number is that far
# from the measurement and why the measurement is printed next to it.
OP_TIMEOUT_S = 60.0
LONG_TIMEOUT_S = 180.0

# docs/ERRORS.md §1. A non-zero exit outside this set is a defect whatever the
# operation was: the taxonomy is the contract a calling script reads.
VALID_EXITS = {0, 1, 2, 3, 4, 5, 6, 7}

APP_ID = "wl.explore"


def die(msg):
    sys.stderr.write("explore: %s\n" % msg)
    sys.exit(2)


def host_load():
    try:
        with open("/proc/loadavg") as f:
            return f.read().split()[:3]
    except OSError:
        return ["?", "?", "?"]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def digest_of(obj):
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def percentiles(xs):
    if not xs:
        return {}
    s = sorted(xs)

    def p(q):
        i = min(len(s) - 1, int(round(q * (len(s) - 1))))
        return round(s[i], 1)
    return {"n": len(s), "min": round(s[0], 1), "median": round(statistics.median(s), 1),
            "p95": p(0.95), "p99": p(0.99), "max": round(s[-1], 1)}


# --------------------------------------------------------------------------- #
#  The CLI, as a black box                                                    #
# --------------------------------------------------------------------------- #

class Cli:
    """Runs `lexe`, records everything, and never reads inside LEXE_HOME.

    One instance per LEXE_HOME. `journal` accumulates every invocation, so a
    failing case can be replayed and minimised from the record alone.
    """

    def __init__(self, binary, home, extra_env=None):
        self.binary = binary
        self.home = home
        self.extra_env = dict(extra_env or {})
        self.journal = []

    def env(self, overrides=None):
        e = {
            "PATH": PINNED_PATH,
            "LEXE_HOME": self.home,
            "HOME": os.path.join(os.path.dirname(self.home), "fakehome"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            # Headless by construction: an automated run must never put a window
            # on anyone's screen, and a result that depends on a live session is
            # not reproducible. Mirrors tests/acceptance/lib.sh.
            "GDK_BACKEND": "x11",
            "QT_QPA_PLATFORM": "offscreen",
            "XDG_SESSION_TYPE": "tty",
        }
        e.update(self.extra_env)
        e.update(overrides or {})
        return {k: v for k, v in e.items() if v is not None}

    def __call__(self, *args, timeout=OP_TIMEOUT_S, env_overrides=None,
                 stdin=None, label=None):
        argv = [self.binary] + [str(a) for a in args]
        t0 = time.time()
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               errors="replace", timeout=timeout,
                               env=self.env(env_overrides), input=stdin,
                               cwd=self.home)
            rc, out, err, timed_out = p.returncode, p.stdout, p.stderr, False
        except subprocess.TimeoutExpired as e:
            rc, timed_out = -1, True
            out = _text(e.stdout)
            err = _text(e.stderr)
        ms = (time.time() - t0) * 1000.0
        rec = {"op": label or " ".join(str(a) for a in args[:2]),
               "argv": [str(a) for a in args], "rc": rc, "ms": round(ms, 1),
               "timed_out": timed_out, "out": out, "err": err}
        # The JOURNAL holds a trimmed copy; the RETURNED record holds the whole
        # output. Trimming what the caller parses was this engine's own first
        # defect: `lexe info --json` for a package carrying a 4096-character
        # argument is longer than 4000 characters, so a 4000-character cap turned
        # a perfectly coherent installation into nine "the runtime lists an app
        # with no active version" failures. The truncation belongs where the text
        # is read by a human, never where it is read by a parser.
        self.journal.append(dict(rec, out=out[:4000], err=err[:4000]))
        return rec

    def json_of(self, *args, **kw):
        r = self(*args, **kw)
        try:
            return r, json.loads(r["out"])
        except Exception:
            return r, None


def _text(x):
    if x is None:
        return ""
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else str(x)


# What a refusal means, reduced to something two runs can be compared on. A
# class, not a code: pinning every code would make the engine a transcript of the
# implementation, and comparing raw prose would make it a transcript of its
# messages.
def outcome_class(rec):
    if rec["timed_out"]:
        return "TIMEOUT"
    rc = rec["rc"]
    if rc == 0:
        return "OK"
    if rc < 0 or rc > 128:
        return "CRASH:%d" % rc
    if rc not in VALID_EXITS:
        return "OFF-TAXONOMY:%d" % rc
    return "REFUSE:%d" % rc


CRASH_MARKERS = (
    "terminate called", "Segmentation fault", "std::bad_alloc",
    "*** stack smashing", "AddressSanitizer", "UndefinedBehaviorSanitizer",
    "libc++abi", "what():  std::", "Aborted (core dumped)",
)


def crashed(rec):
    """A refusal is fine. An unhandled exception reaching the terminal is not.

    Checked on text as well as on the exit code, because a runtime that catches
    everything at main() can report a tidy exit 1 having already printed a
    `terminate called` banner — and the banner is the defect.
    """
    if rec["timed_out"]:
        return "hung past the timeout"
    if rec["rc"] < 0 or rec["rc"] > 128:
        return "exited on a signal (rc=%d)" % rec["rc"]
    blob = rec["out"] + rec["err"]
    for m in CRASH_MARKERS:
        if m in blob:
            return "printed %r" % m
    if rec["rc"] not in VALID_EXITS:
        return "exit %d is outside the docs/ERRORS.md §1 taxonomy" % rec["rc"]
    return None


# --------------------------------------------------------------------------- #
#  The corpus, and fixtures made from it                                      #
# --------------------------------------------------------------------------- #

class Corpus:
    """The workload index, read without assuming how big it is.

    Role C is growing this corpus toward several hundred specimens, so nothing
    here counts them or hard-codes an id outside `PREFERRED`. A family that is
    absent is reported as a gap, never as a failure: a sampler that FAILS because
    a fixture it wanted does not exist is reporting on itself.
    """

    # Specimens whose oracle answers a question this file needs to ask. Each is a
    # preference, with a family-level fallback, so a renamed specimen degrades to
    # "less specific coverage" rather than to a red lane.
    PREFERRED = {
        "plain": ("linux-outcome-exit-0", "outcome"),
        "alt": ("linux-io-both-streams", "io"),
        "args": ("linux-arg-basic-flags", "interface"),
        "args_unicode": ("linux-arg-unicode", "interface"),
        "env_present": ("linux-env-declared-present", "interface"),
        "env_absent": ("linux-env-absent", "interface"),
        "cwd": ("linux-fs-path-environment", "filesystem"),
        "long": ("linux-run-bounded-3s", None),
    }

    def __init__(self, index_path):
        with open(index_path) as f:
            self.index = json.load(f)
        self.root = self.index.get("corpus_root") or os.path.dirname(index_path)
        self.specimens = [s for s in self.index["specimens"]
                          if s.get("verdict", {}).get("status") == "baseline-ok"]
        self.by_id = {s["id"]: s for s in self.specimens}
        self.gaps = []

    def pick(self, role):
        """The specimen for a role, or None with the gap recorded."""
        want, family = self.PREFERRED[role]
        if want in self.by_id:
            return self.by_id[want]
        if family:
            cands = sorted((s for s in self.specimens if s.get("family") == family),
                           key=lambda s: s["id"])
            if cands:
                self.gaps.append("role %r: %s absent, substituted %s"
                                 % (role, want, cands[0]["id"]))
                return cands[0]
        self.gaps.append("role %r: no specimen available (wanted %s)" % (role, want))
        return None

    def families(self):
        return sorted({s.get("family", "?") for s in self.specimens})

    def sample_of_family(self, family, rng):
        c = sorted(s["id"] for s in self.specimens if s.get("family") == family)
        return self.by_id[rng.choice(c)] if c else None

    def baseline_lines(self, spec):
        runs = spec.get("baseline", {}).get("runs") or []
        return runs[0].get("oracle_deterministic_lines", []) if runs else []

    def baseline_keys(self, spec):
        runs = spec.get("baseline", {}).get("runs") or []
        return sorted(runs[0].get("oracle", {}).keys()) if runs else []

    def baseline_exit(self, spec):
        runs = spec.get("baseline", {}).get("runs") or []
        return runs[0].get("exit_code") if runs else None

    def binary_of(self, spec):
        return spec.get("binary", {}).get("path")


class Factory:
    """Builds signed .lexe packages, caching by content so packing happens once.

    `pack` costs ~80ms and installs cost ~27ms, so a run of ten thousand
    sequences must not re-pack. The cache key is every input that can change the
    bytes.
    """

    def __init__(self, lexe, root, corpus):
        self.lexe = lexe
        self.root = root
        self.corpus = corpus
        self.cache = {}
        # The engines run their cases on a thread pool, and several threads ask
        # for the same package in the same instant. Without this lock two of them
        # create the same staging directory and one dies with FileExistsError —
        # which is how the first full race run ended, 336 schedules into nothing.
        # The lock is coarse because packing is ~80ms and cached after the first
        # call; contention here is not worth a finer-grained scheme.
        self.lock = threading.Lock()
        os.makedirs(root, exist_ok=True)
        self.keys = {}
        for name in ("main", "other"):
            kp = os.path.join(root, "key-%s.json" % name)
            if not os.path.exists(kp):
                r = subprocess.run([lexe, "keygen", kp], capture_output=True,
                                   text=True, env={"PATH": PINNED_PATH})
                if r.returncode != 0:
                    die("keygen failed: %s" % r.stderr.strip())
            with open(kp) as f:
                self.keys[name] = (kp, json.load(f)["publicKey"])

    def package(self, spec, version="1.0.0", *, app_id=APP_ID, key="main",
                launch_mode="console", args=(), permissions=(),
                extra_files=None, updates=None):
        ident = dict(spec_id=spec["id"], version=version, app_id=app_id, key=key,
                     launch_mode=launch_mode, args=list(args),
                     permissions=list(permissions),
                     extra=sorted((extra_files or {}).items()), updates=updates)
        ck = digest_of(ident)[:16]
        with self.lock:
            if ck in self.cache:
                return self.cache[ck]
            return self._build(ck, spec, version, app_id, key, launch_mode,
                               args, permissions, extra_files, updates)

    def _build(self, ck, spec, version, app_id, key, launch_mode, args,
               permissions, extra_files, updates):
        stage = os.path.join(self.root, "stage-" + ck)
        shutil.rmtree(stage, ignore_errors=True)
        os.makedirs(os.path.join(stage, "bin"))
        src = self.corpus.binary_of(spec)
        if not src or not os.path.exists(src):
            return None
        shutil.copy2(src, os.path.join(stage, "bin", "prog"))
        os.chmod(os.path.join(stage, "bin", "prog"), 0o755)
        for rel, content in (extra_files or {}).items():
            p = os.path.join(stage, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(content)
        manifest = {
            "lexeVersion": "0.1", "id": app_id, "name": "explore subject",
            "version": version,
            "publisher": {"name": "workload-corpus",
                          "publicKey": self.keys[key][1]},
            "applicationType": "native", "architectures": ["x86_64"],
            "entrypoint": {"executable": "bin/prog", "arguments": list(args)},
            "launch": {"mode": launch_mode},
            "install": {"scope": "user", "mode": "bundled"},
            "permissions": list(permissions),
        }
        if updates:
            manifest["updates"] = updates
        mpath = os.path.join(self.root, "m-%s.json" % ck)
        with open(mpath, "w") as f:
            json.dump(manifest, f, indent=2)
        out = os.path.join(self.root, "pkg-%s.lexe" % ck)
        r = subprocess.run([self.lexe, "pack", stage, "--manifest", mpath,
                            "--key", self.keys[key][0], "-o", out],
                           capture_output=True, text=True,
                           env={"PATH": PINNED_PATH})
        if r.returncode != 0 or not os.path.exists(out):
            self.cache[ck] = None
            return None
        self.cache[ck] = out
        return out


# --------------------------------------------------------------------------- #
#  Observation: the outside of the runtime only                               #
# --------------------------------------------------------------------------- #

# The reference implementation's on-disk layout is documented in
# REFERENCE-POLICY.md and is explicitly NOT part of the format (FORMAT-0.1 §9
# names no path). Three things in this file do touch it, and they are collected
# here so the dependency is visible in one place rather than smeared through the
# engines:
#
#   * inducing damage — there is no CLI verb for "corrupt this installation", and
#     without one the whole DAMAGED half of §9.2 cannot be tested at all;
#   * the lock and lease files — used as the concurrency TRIGGER, i.e. to know
#     when a mutation has actually entered its critical section, because timing a
#     sleep instead would be probability rather than forcing;
#   * checking that a running version's files survived an operation (§9.4), which
#     is a statement about files.
#
# Every one of them is an INPUT or a side-channel, never the oracle for a
# verdict. Whether an application works is always answered by running it.
def version_dir(home, app_id, version):
    return os.path.join(home, "apps", app_id, "versions", version)


def lock_path(home, app_id):
    return os.path.join(home, "locks", "%s.lock" % app_id)


def lease_path(home, app_id, version):
    return os.path.join(home, "locks", "%s.v.%s.lease" % (app_id, version))


class Observed:
    """The externally visible state of one application, and nothing else.

    Built from `lexe list --json`, `lexe info <id> --json` and — where the
    question is "does it work" — from running it and recognising the program by
    its own oracle. The `damaged` field is a CONCLUSION from behaviour, not a
    field anyone reported.
    """

    def __init__(self, installed, active, retained, launchable, run_class,
                 run_stdout, notes):
        self.installed = installed
        self.active = active
        self.retained = retained
        self.launchable = launchable
        self.run_class = run_class
        self.run_stdout = run_stdout
        self.notes = notes

    def as_dict(self):
        return {"installed": self.installed, "active": self.active,
                "retained": self.retained, "launchable": self.launchable,
                "run_class": self.run_class, "notes": self.notes}

    def state_name(self):
        """Collapse to one of the named lifecycle states, from outside."""
        if not self.installed:
            return "ABSENT"
        if not self.launchable:
            return "DAMAGED"
        if self.active and self.retained and self.active != max(self.retained):
            return "ROLLED_BACK"
        if len(self.retained) > 1:
            return "UPDATED"
        return "INSTALLED"


def observe_on_disk(home, app_id):
    """The installed state read from the FILESYSTEM, without asking the runtime.

    The second observation of "the transaction really committed". Every other
    check in this file learns the store's state by running `lexe list` and
    `lexe info` and parsing what they print — one mechanism, so one defect in it
    is invisible to all of them at once. A promote that renamed the version
    directory but not the `current` pointer, a `current` advanced over a version
    directory that was never created, or a record written for a version whose
    payload is absent would all be reported by the runtime exactly as a healthy
    install, and no amount of re-reading its output would say otherwise.

    The layout is docs/REFERENCE-POLICY.md §2, and that document says in as many
    words that the layout is a reference-implementation choice. So this is
    deliberately advisory: it reports `known=False` when the directory is not
    where the document says, rather than manufacturing a violation out of a
    layout change. What it must never do is report `known=True` and a wrong
    answer, which is why every field is None unless it was actually read.
    """
    app = os.path.join(home, "apps", app_id)
    out = {"known": os.path.isdir(app), "current": None, "versions": [],
           "current_target_exists": None, "has_manifest": None}
    if not out["known"]:
        return out
    vdir = os.path.join(app, "versions")
    if os.path.isdir(vdir):
        out["versions"] = sorted(n for n in os.listdir(vdir)
                                 if os.path.isdir(os.path.join(vdir, n)))
    cur = os.path.join(app, "current")
    curtxt = os.path.join(app, "current.txt")
    if os.path.islink(cur):
        target = os.readlink(cur)
        out["current"] = os.path.basename(target.rstrip("/"))
        out["current_target_exists"] = os.path.exists(
            os.path.join(app, target) if not os.path.isabs(target) else target)
    elif os.path.isfile(curtxt):
        try:
            out["current"] = open(curtxt).read().strip()
        except OSError:
            out["current"] = None
        if out["current"]:
            out["current_target_exists"] = os.path.isdir(
                os.path.join(vdir, out["current"]))
    out["has_manifest"] = os.path.isfile(os.path.join(app, "manifest.json"))
    return out


def observe(cli, app_id, *, probe_run=True):
    notes = []
    listed = cli("list", "--json", label="observe:list")
    installed = False
    try:
        rows = json.loads(listed["out"])
        installed = any(r.get("id") == app_id for r in rows) if isinstance(rows, list) else \
            app_id in listed["out"]
    except Exception:
        installed = app_id in listed["out"]
        notes.append("list --json was not parseable JSON")
    active, retained = None, []
    if installed:
        _, info = cli.json_of("info", app_id, "--json", label="observe:info")
        if info and isinstance(info.get("installed"), dict):
            active = info["installed"].get("version")
            retained = list(info["installed"].get("versions") or [])
        else:
            notes.append("info --json gave no installed block for a listed app")
    launchable, run_class, run_out = None, None, ""
    if installed and probe_run:
        r = cli("run", app_id, label="observe:run")
        run_class = outcome_class(r)
        run_out = r["out"]
        launchable = (r["rc"] == 0)
    return Observed(installed, active, retained, launchable, run_class, run_out, notes)


# --------------------------------------------------------------------------- #
#  TASK 2 — an independent abstract model of the lifecycle                    #
# --------------------------------------------------------------------------- #
#
# Written from FORMAT-0.1 §9, docs/ERRORS.md §1 and docs/CONCURRENCY.md. It shares
# no code, no type and no vocabulary with the runtime's own state handling, which
# is the whole point: a model built on the implementation's notion of state cannot
# contradict it.
#
# Three kinds of expectation, and the difference matters more than the table:
#
#   PIN(code)   the documents decide it. A different answer is a divergence, and
#               the citation says which sentence was broken.
#   ANY_REFUSE  the documents require a refusal but name no code. Any taxonomy
#               code passes; a 0 does not.
#   UNDERSPEC   the documents do not decide. The model records what happened and
#               asserts nothing about WHICH answer is right — but the engine still
#               requires the answer be the same every time this abstract state is
#               reached, by any path. That consistency property needs no spec, and
#               it is the one an implementation cannot satisfy by accident.
#
# Deriving the "right" answer for an UNDERSPEC cell by reading the runtime's source
# is forbidden here. It would convert a spec gap into a passing test and lose the
# finding.

PIN = "PIN"
ANY_REFUSE = "ANY_REFUSE"
UNDERSPEC = "UNDERSPEC"

OPS = ("verify", "install", "install_newer", "install_older", "install_same",
       "install_other_key", "run", "stop", "update", "rollback", "repair",
       "doctor", "doctor_repair", "uninstall", "uninstall_purge")


class Abstract:
    """The model's state. Deliberately a plain record, not a class hierarchy."""

    def __init__(self):
        self.present = False
        self.active = None            # version string
        self.retained = []            # versions on disk, ascending
        self.prev = None              # the rollback target, if an update applied
        # Damage is PER VERSION, and that is not a detail. The first model kept
        # one global health flag, and it produced eight disagreements across
        # 10,000 sequences that all had the same shape: damage 1.0.0, install
        # 2.0.0 (model resets health), roll back to 1.0.0 — the model says healthy,
        # the runtime correctly still has a damaged 1.0.0 — and the mirror image,
        # where rolling back AWAY from a damaged version made the model expect a
        # refusal and the application run perfectly. FORMAT-0.1 §9.1 says an
        # installed version is identified by the PAIR (App ID, version), so its
        # integrity is a property of the pair too. The runtime had this right and
        # the model did not.
        self.damaged = {}             # version -> "MODIFIED" | "MISSING"
        self.running = False          # a console launch in flight
        self.service = False
        self.data_retained = False    # persistent data survives removal (§9.5)
        self.data_key = None          # the publisher key that owns retained data
        # The publisher key this App ID is bound to locally. docs/ERRORS.md
        # describes ChangedKeyError as a LOCAL record; the model has to carry it
        # because without it an `install` that is refused with exit 7 looks like a
        # broken install path. The first version of this model omitted it and
        # reported six healthy refusals as runtime defects.
        self.bound_key = None
        self.purged = False           # data purged since the binding was made
        # Desktop integration is MACHINE state, not application state, and
        # `doctor` reports on it. Carried here because leaving it out made the
        # consistency oracle flag `doctor` as answering the same abstract state
        # two different ways: measured across 60 sequences, 0 of 27 non-zero
        # doctor runs had a prior successful install or `doctor --repair`, and
        # 22 of 22 zero-exit runs did. The runtime was consistent; the model's
        # equivalence class was too coarse. Whether an UNINSTALL takes the
        # integration away again is not modelled and not guessed — if it does,
        # the oracle will say so.
        self.integrated = False

    def copy(self):
        return copy.deepcopy(self)

    def health_of(self, version=None):
        return self.damaged.get(version if version is not None else self.active,
                                "OK")

    def name(self):
        if not self.present:
            return "ABSENT"
        if self.health_of() == "MODIFIED":
            return "REPAIRABLE"
        if self.health_of() == "MISSING":
            return "DAMAGED"
        if self.service:
            return "SERVICE_RUNNING"
        if self.running:
            return "RUNNING"
        if self.prev and self.active != max(self.retained or [self.active]):
            return "ROLLED_BACK"
        if self.prev:
            return "UPDATED"
        return "INSTALLED"

    def key(self):
        """The equivalence class used by the consistency oracle.

        Coarse on purpose. Two states in the same class must answer every
        operation identically; if they do not, either the class is too coarse (a
        model defect, and the report says so) or the runtime is history-dependent
        in a way nothing observable justifies.
        """
        return (self.name(), self.health_of(), bool(self.prev), len(self.retained),
                self.running, self.service, self.data_retained, self.bound_key,
                self.purged, self.integrated)

    def as_dict(self):
        return {k: v for k, v in vars(self).items()}


# An INJECTED fault, for testing the minimiser rather than the runtime.
#
# TASK 3 asks for machinery that reduces a failing trace to a minimal
# reproducer. When the runtime disagrees with nothing, there is no failing trace
# to reduce, and "the minimiser was not exercised" is indistinguishable from
# "the minimiser works". So a fault can be injected into the MODEL: --inject
# rollback:ABSENT:0 makes the model insist that `rollback` on an absent
# application must exit 0. It does not, so every sequence containing that step
# diverges, and the minimal reproducer is known in advance to be the single
# operation. The self-test asserts the reducer finds exactly that.
#
# This changes only the model. The runtime is untouched, and no injected fault
# can ever make a real finding disappear.
INJECT = {}


def parse_inject(spec):
    if not spec:
        return {}
    op, state, codes = spec.split(":", 2)
    return {(op, state): {int(c) for c in codes.split(",")}}


class Model:
    """expect(state, op) -> (kind, codes, next_state, citation)"""

    @staticmethod
    def expect(s, op):
        hit = INJECT.get((op, s.name()))
        if hit is not None:
            return (PIN, hit, s.copy(),
                    "INJECTED FAULT (--inject): not a statement about .LEXE")
        return Model._expect(s, op)

    @staticmethod
    def _expect(s, op):
        n = s.copy()

        # ---- verify: a property of a FILE, so no state can change the answer.
        if op == "verify":
            return PIN, {0}, n, ("FORMAT-0.1 §6: verification is a function of "
                                 "the package bytes; installed state is not an input")

        # ---- install, in its several shapes
        if op in ("install", "install_newer", "install_older", "install_same",
                  "install_other_key"):
            key = "other" if op == "install_other_key" else "main"
            # Identity first. A trust decision outranks everything else about the
            # package, and docs/ERRORS.md §1 says exit 7 is never bypassable.
            if s.bound_key is not None and s.bound_key != key:
                if s.purged:
                    # FORMAT-0.1 §9.5.1 says a purge discards the permission
                    # APPROVAL. It does not say whether the local key BINDING
                    # survives one, and docs/ERRORS.md describes ChangedKeyError as
                    # "a local record" without stating its lifetime. Left open on
                    # purpose: deciding it here by watching what the runtime does
                    # would convert a real gap into a passing test.
                    return (UNDERSPEC, VALID_EXITS, n,
                            "neither FORMAT-0.1 §9.5 nor docs/ERRORS.md says "
                            "whether purging an application's data also discards "
                            "the local App-ID/key binding")
                return (PIN, {7}, n,
                        "docs/ERRORS.md §1: a signing key that differs from the one "
                        "bound to this App ID locally is ChangedKeyError, exit 7, "
                        "and exit 7 is never bypassable — not by --yes, --force or "
                        "--accept-permissions")
            if s.bound_key is None and s.data_retained and s.data_key != key:
                return (PIN, {6}, n,
                        "FORMAT-0.1 §9.5: data retained under a different publisher "
                        "key MUST NOT be inherited, and the runtime MUST refuse "
                        "rather than guess; docs/ERRORS.md maps "
                        "RetainedDataConflict to 6")
            if not s.present:
                n.present = True
                n.active = "1.0.0"
                n.retained = sorted(set(s.retained + [n.active]))
                n.damaged.pop(n.active, None)
                n.bound_key = key
                n.data_retained, n.data_key, n.purged = True, key, False
                n.integrated = True
                return PIN, {0}, n, "FORMAT-0.1 §9.2: a completed install is reachable"
            if op == "install_other_key":
                # Present, and the key matches the binding: this is simply another
                # install of the version that is already current.
                op = "install_same"
            if s.running and op == "install_same":
                # Replacing the RUNNING version's content is exactly what §9.4
                # forbids, so a refusal is required here even though the plain
                # install-same case is underspecified.
                return (ANY_REFUSE, VALID_EXITS - {0}, n,
                        "FORMAT-0.1 §9.4: an operation MUST NOT modify the files "
                        "of a version that is currently executing")
            if op == "install_newer":
                n.prev = s.active
                n.active = "2.0.0" if s.active == "1.0.0" else "3.0.0"
                n.retained = sorted(set(s.retained + [n.active]))
                n.damaged.pop(n.active, None)
                return PIN, {0}, n, ("FORMAT-0.1 §9.1: two versions of one "
                                     "application MUST be able to coexist")
            # install_same / install_older over an existing installation: nothing
            # in FORMAT-0.1 decides this. Left open, deliberately. §7.7 fixes what
            # an UPDATE may offer; it says nothing about a direct install.
            return (UNDERSPEC, VALID_EXITS, n,
                    "FORMAT-0.1 is silent on re-installing the current version or "
                    "installing an older one by hand (§7.7 governs UPDATES, not "
                    "a direct install)")

        # ---- run
        if op == "run":
            if not s.present:
                return (PIN, {4}, n,
                        "docs/ERRORS.md §1: no such application is NotFoundError, 4")
            if s.health_of() != "OK":
                return (ANY_REFUSE, {1, 3}, n,
                        "FORMAT-0.1 §9.2: an application that reports as installed "
                        "MUST be launchable or MUST report honestly that it is "
                        "damaged — it MUST NOT silently be missing files")
            return PIN, {0}, n, "FORMAT-0.1 §9.2: a healthy installation launches"

        # ---- stop. There is no `lexe stop`; see STOP_GAP below.
        if op == "stop":
            return (UNDERSPEC, VALID_EXITS, n,
                    "the CLI has no `stop` verb; see STOP_GAP")

        # ---- update (through a source document, §7)
        if op == "update":
            if not s.present:
                return PIN, {4}, n, "docs/ERRORS.md §1: NotFoundError is 4"
            return (UNDERSPEC, VALID_EXITS, n,
                    "FORMAT-0.1 §7 fixes which OFFERS are acceptable, not the exit "
                    "code for 'no source configured' or 'nothing newer'")

        # ---- rollback
        if op == "rollback":
            if not s.present:
                return PIN, {4}, n, "docs/ERRORS.md §1: NotFoundError is 4"
            if not s.prev:
                return (ANY_REFUSE, VALID_EXITS - {0}, n,
                        "FORMAT-0.1 §9.3 guarantees a return to the IMMEDIATELY "
                        "PREVIOUS version; with no update applied there is no such "
                        "version, so the operation cannot succeed")
            n.active, n.prev = s.prev, None
            return (PIN, {0}, n,
                    "FORMAT-0.1 §9.3: the runtime MUST be able to return to the "
                    "immediately previous version, and it MUST be the content "
                    "originally verified and installed")

        # ---- repair
        if op == "repair":
            if not s.present:
                return PIN, {4}, n, "docs/ERRORS.md §1: NotFoundError is 4"
            n.damaged.pop(s.active, None)
            return (PIN, {0}, n,
                    "FORMAT-0.1 §9.1: a runtime MAY modify a version's files to "
                    "repair it to its verified content, and §9.2 forbids leaving "
                    "an installed application silently unlaunchable")

        # ---- doctor: about the machine, not about one application
        if op in ("doctor", "doctor_repair"):
            if op == "doctor_repair":
                n.integrated = True
            return (UNDERSPEC, VALID_EXITS, n,
                    "docs/ERRORS.md §1 lists which inspection commands carry a "
                    "typed exit (`verify`, `sdk verify`, `analyze`) and does not "
                    "mention `doctor`; see DOCTOR_GAP")

        # ---- uninstall
        if op in ("uninstall", "uninstall_purge"):
            if not s.present:
                return PIN, {4}, n, "docs/ERRORS.md §1: NotFoundError is 4"
            if s.running or s.service:
                return (PIN, {6}, n,
                        "docs/CONCURRENCY.md: uninstall while launching is refused "
                        "with BusyError, never a silent deletion under a live "
                        "process; FORMAT-0.1 §9.4 requires the refusal")
            n.present, n.active, n.retained, n.prev = False, None, [], None
            n.damaged = {}
            if op == "uninstall_purge":
                n.data_retained, n.data_key, n.purged = False, None, True
            return (PIN, {0}, n,
                    "FORMAT-0.1 §9.5: removal of persistent data requires a "
                    "separate explicit instruction, so a plain removal succeeds "
                    "and keeps the data")

        raise AssertionError("unmodelled op %r" % op)


# Two gaps the model names rather than papers over. Both are reported as findings,
# and both are the reason the corresponding cells are UNDERSPEC above.
STOP_GAP = (
    "the lifecycle operation set includes `stop`, and the CLI has no such verb "
    "(`lexe --help` offers no stop/kill/terminate). A service launched with "
    "launch.mode=service can be started by the runtime and can only be stopped by "
    "signalling the launcher from outside it, which is not an operation the "
    "runtime offers or documents. FORMAT-0.1 §5.6 defines the mode; nothing "
    "defines its termination.")

DOCTOR_GAP = (
    "docs/ERRORS.md §1 states that the inspection commands carry a typed exit "
    "rather than always returning 0, and names `verify`, `sdk verify` and "
    "`analyze` — the last of which was changed precisely because 'a pre-ship gate "
    "which always succeeds is not a gate'. `doctor` is an inspection command with "
    "a --json verdict containing `ok` and `problems`, and it is not in that list. "
    "MEASURED, before concluding anything from the omission: `doctor` DOES carry a "
    "typed exit — it exits 1 while problems remain and 0 once they are repaired "
    "(27 of 27 non-zero runs had no prior repair; 22 of 22 zero-exit runs did). So "
    "this is a DOCUMENTATION gap and not a missing gate: a script may rely on the "
    "behaviour, and nothing tells it that it may. The check below asserts the "
    "property no reading can dispute — that `doctor --repair` CONVERGES.")


# --------------------------------------------------------------------------- #
#  TASK 1 — the dimensions, and a deterministic pairwise sampler              #
# --------------------------------------------------------------------------- #

# Ten dimensions. A value is a small identifier the engines interpret; the
# interpretation lives next to the code that applies it, so adding a value is a
# one-line change in two places rather than a new combinatorial special case.
#
# Availability is resolved at plan time, not at assert time: a chain that this
# host cannot run is removed from its dimension and recorded as a gap, so the
# sampler still guarantees pairwise coverage over what is actually reachable
# instead of guaranteeing it over a fiction.
DIMENSIONS = {
    "specimen": ["plain", "alt", "args", "args_unicode", "env_present",
                 "env_absent", "cwd"],
    "payload": ["native-elf"],                 # extended when a corpus is present
    "chain": ["native"],                       # extended from `lexe runtime list`
    "launch_mode": ["console", "gui", "service"],
    "sandbox": ["default", "network-requested"],
    "arguments": ["none", "declared", "extra-unicode", "extra-long",
                  "dash-dash-passthrough"],
    "environment": ["minimal", "authority-vars-set", "unicode-value",
                    "no-locale"],
    "filesystem": ["clean", "data-prepopulated", "stale-cache", "leftover-lock"],
    "lifecycle": ["fresh", "after-update", "after-rollback", "after-repair",
                  "after-damage-repair"],
    "concurrency": ["none", "cpu-pressure", "concurrent-reader"],
}


def pairwise_plan(dims, seed, order=2):
    """Greedy IPOG-style all-pairs (or all-triples) generator.

    Deterministic for a given (dims, seed, order): the only nondeterminism is the
    tie-break among equally good candidates, and that draws from `rng`. The
    guarantee is checked rather than assumed — `coverage_gaps` re-derives every
    required tuple from the plan and the engine FAILS if any is missing. A sampler
    that claims pairwise coverage and does not verify it is claiming, not
    covering.
    """
    rng = random.Random("pairwise|%s|%d" % (seed, order))
    names = list(dims.keys())
    required = set()
    for combo in itertools.combinations(names, order):
        for vals in itertools.product(*(dims[n] for n in combo)):
            required.add((combo, vals))

    plan = []
    guard = 0
    while required and guard < 100000:
        guard += 1
        # Build one case greedily: at each dimension pick the value that covers
        # the most still-required tuples with what has been fixed so far.
        case = {}
        for name in names:
            best, best_gain = None, -1
            cands = list(dims[name])
            rng.shuffle(cands)
            for v in cands:
                trial = dict(case)
                trial[name] = v
                gain = 0
                for combo, vals in required:
                    if name not in combo:
                        continue
                    if all(k in trial for k in combo) and \
                            tuple(trial[k] for k in combo) == vals:
                        gain += 1
                if gain > best_gain:
                    best, best_gain = v, gain
            case[name] = best
        newly = {(c, v) for (c, v) in required
                 if tuple(case[k] for k in c) == v}
        if not newly:
            # No progress is possible with this greedy pass; take the first
            # uncovered tuple and build a case around it directly.
            combo, vals = sorted(required, key=lambda t: (t[0], t[1]))[0]
            case = {n: rng.choice(dims[n]) for n in names}
            for k, v in zip(combo, vals):
                case[k] = v
            newly = {(c, v) for (c, v) in required
                     if tuple(case[k] for k in c) == v}
        required -= newly
        plan.append(case)
    return plan


def coverage_gaps(dims, plan, order=2):
    required = set()
    names = list(dims.keys())
    for combo in itertools.combinations(names, order):
        for vals in itertools.product(*(dims[n] for n in combo)):
            required.add((combo, vals))
    for case in plan:
        for combo, vals in list(required):
            if tuple(case[k] for k in combo) == vals:
                required.discard((combo, vals))
    return sorted(required)


def case_id(seed, case):
    return digest_of({"seed": seed, "case": case})[:12]


# --------------------------------------------------------------------------- #
#  Pinned §9.5.1 scenarios — permission approval is bound to the APPLICATION  #
# --------------------------------------------------------------------------- #
#
# These are not part of the random walk. §9.5.1 decides a question that is easy to
# implement backwards and impossible to discover by shuffling operations, because
# the interesting behaviour is a NON-event: a second prompt that must not happen.
# Each step pins an exit code and cites the sentence it comes from.
#
#   perms=()          a package requesting nothing
#   perms=(network,)  a package requesting one permission from the frozen 0.1
#                     vocabulary (schema/: exactly "network" and
#                     "user-files-selected")
PERMISSION_SCENARIOS = [
    {
        "id": "bare-yes-does-not-approve",
        "why": ("FORMAT-0.1 §9.5.1: an update whose permission set EXPANDS must be "
                "refused until explicitly approved, and 'a bare confirmation MUST "
                "NOT satisfy it'. docs/ERRORS.md §1 maps PermissionError to 5."),
        "steps": [
            ("install", {"perms": (), "version": "1.0.0",
                         "flags": ("--yes", "--trust")}, {0}),
            ("install", {"perms": ("network",), "version": "2.0.0",
                         "flags": ("--yes",)}, {5}),
        ],
    },
    {
        "id": "explicit-approval-admits-the-expansion",
        "why": ("the same sentence, in the other direction: an expansion that IS "
                "explicitly approved must be admitted, or the refusal above is "
                "just a broken install path rather than a consent gate."),
        "steps": [
            ("install", {"perms": (), "version": "1.0.0",
                         "flags": ("--yes", "--trust")}, {0}),
            ("install", {"perms": ("network",), "version": "2.0.0",
                         "flags": ("--yes", "--accept-permissions")}, {0}),
        ],
    },
    {
        "id": "approval-survives-rollback-and-is-not-re-requested",
        "why": ("FORMAT-0.1 §9.5.1, stated as a consequence nobody should be "
                "surprised by: approving `network` for 2.0.0, rolling back to a "
                "1.0.0 that requests nothing, and updating to 2.0.0 again will NOT "
                "prompt a second time. A rollback does not narrow the approval."),
        "steps": [
            ("install", {"perms": (), "version": "1.0.0",
                         "flags": ("--yes", "--trust")}, {0}),
            ("install", {"perms": ("network",), "version": "2.0.0",
                         "flags": ("--yes", "--accept-permissions")}, {0}),
            ("rollback", {}, {0}),
            # No --accept-permissions this time. §9.5.1 says the authority was
            # granted to the application under that key and has not been withdrawn.
            ("install", {"perms": ("network",), "version": "2.0.0",
                         "flags": ("--yes",)}, {0}),
        ],
    },
    {
        "id": "purging-data-discards-the-approval",
        "why": ("FORMAT-0.1 §9.5.1: a runtime MUST discard the approval when the "
                "application's persistent data is purged. The consequence has to "
                "be staged carefully, and the first draft of this scenario got it "
                "wrong: it purged and then did a FRESH install of a "
                "permission-requesting package with a bare --yes, and called the "
                "success a violation. But §9.5.1's MUST is about an UPDATE whose "
                "permission set expands beyond what was approved; a first install "
                "shows its permissions and --yes confirms them, so that step "
                "proved nothing and the scenario was measuring its own mistake. "
                "The observable consequence of a discarded approval is that the "
                "EXPANSION must be refused again, so the expansion is what is "
                "replayed here."),
        "steps": [
            ("install", {"perms": (), "version": "1.0.0",
                         "flags": ("--yes", "--trust")}, {0}),
            ("install", {"perms": ("network",), "version": "2.0.0",
                         "flags": ("--yes", "--accept-permissions")}, {0}),
            ("remove_purge", {}, {0}),
            ("install", {"perms": (), "version": "1.0.0",
                         "flags": ("--yes", "--trust")}, {0}),
            # The same expansion as before, with a bare confirmation. If the purge
            # discarded the approval this must be refused with 5, exactly as in
            # the first scenario. If it succeeds, an approval outlived the data it
            # was supposed to die with.
            ("install", {"perms": ("network",), "version": "2.0.0",
                         "flags": ("--yes",)}, {5}),
        ],
    },
    {
        "id": "retained-data-under-another-key-is-refused",
        "why": ("FORMAT-0.1 §9.5: a package signed by a DIFFERENT key MUST NOT be "
                "given access to data retained under the previous key, and the "
                "runtime MUST refuse rather than guess. docs/ERRORS.md maps "
                "RetainedDataConflict to 6 and ChangedKeyError to 7, so either is "
                "a correct refusal; a 0 is not."),
        "steps": [
            ("install", {"perms": (), "version": "1.0.0",
                         "flags": ("--yes", "--trust")}, {0}),
            ("run", {}, {0}),
            ("remove", {}, {0}),
            ("install", {"perms": (), "version": "1.0.0", "key": "other",
                         "flags": ("--yes", "--trust")}, {6, 7}),
        ],
    },
]


# --------------------------------------------------------------------------- #
#  A workspace: one scratch LEXE_HOME, and the actions the engines apply       #
# --------------------------------------------------------------------------- #

class Workspace:
    def __init__(self, cfg, tag):
        self.cfg = cfg
        self.dir = tempfile.mkdtemp(prefix="explore-%s-" % tag, dir=cfg.scratch)
        self.home = os.path.join(self.dir, "home")
        os.makedirs(self.home)
        os.makedirs(os.path.join(self.dir, "fakehome"))
        self.cli = Cli(cfg.lexe, self.home)
        self.violations = []
        self.pressure = []

    def close(self):
        for p in self.pressure:
            try:
                p.kill()
            except Exception:
                pass
        if not self.cfg.keep:
            shutil.rmtree(self.dir, ignore_errors=True)

    def violate(self, vid, detail, citation=""):
        self.violations.append({"id": vid, "detail": detail,
                                "citation": citation})

    # -- universal invariants, applied to every operation anywhere -----------
    def check_record(self, rec):
        why = crashed(rec)
        if why:
            self.violate("I1-no-crash", "%s: %s" % (rec["op"], why),
                         "docs/ERRORS.md §1 enumerates every exit a caller may see")

    def check_all_records(self):
        for rec in self.cli.journal:
            self.check_record(rec)

    def check_coherent(self, label):
        """FORMAT-0.1 §9.2, from outside: installed implies launchable-or-honest."""
        o = observe(self.cli, APP_ID)
        if o.installed and o.launchable is False:
            # Not automatically a violation — a DAMAGED installation refusing to
            # launch is the CORRECT behaviour. What is forbidden is refusing with
            # no diagnosis at all, and succeeding while broken.
            r = self.cli.journal[-1]
            if not (r["err"].strip() or r["out"].strip()):
                self.violate("I2-honest-damage",
                             "%s: installed, will not launch, and said nothing"
                             % label,
                             "FORMAT-0.1 §9.2: it MUST report honestly that it is "
                             "damaged — it MUST NOT silently be missing files")
        if o.installed and not o.active:
            self.violate("I2-coherence",
                         "%s: `list` names the app and `info` reports no active "
                         "version" % label,
                         "FORMAT-0.1 §9.2: the set of installed applications and "
                         "the active version of each MUST be mutually consistent")
        self.check_disk_agrees(o, label)
        return o

    def check_disk_agrees(self, o, label):
        """The SECOND observation of the same property, by another mechanism.

        Everything above learned the store's state from the runtime's own
        output. This reads the store. The two cannot fail for the same reason:
        a parser or a reporting bug moves the first and not the second, and a
        promote that half-happened moves the second and not the first.

        Only genuine contradictions are raised. A layout the document does not
        describe makes this observation ABSENT (`known=False`), never a
        violation — docs/REFERENCE-POLICY.md §2 says the layout is a
        reference-implementation choice, and a check that cannot tell "the
        layout moved" from "the store is torn" would report the first as the
        second forever.
        """
        d = observe_on_disk(self.home, APP_ID)
        if not d["known"]:
            return d
        if o.installed and o.active and d["current"] and d["current"] != o.active:
            self.violate("I5-record-vs-disk",
                         "%s: `info` reports active version %s and the store's "
                         "`current` points at %s"
                         % (label, o.active, d["current"]),
                         "FORMAT-0.1 §9.2: the active version of each "
                         "application and the content of that version MUST be "
                         "mutually consistent")
        if o.installed and o.active and d["versions"] and \
                o.active not in d["versions"]:
            self.violate("I5-active-version-absent",
                         "%s: `info` reports active version %s and the store "
                         "holds only %s" % (label, o.active, d["versions"]),
                         "FORMAT-0.1 §9.2: an application that reports as "
                         "installed MUST be launchable, or MUST report honestly "
                         "that it is damaged")
        if d["current"] and d["current_target_exists"] is False:
            self.violate("I5-dangling-current",
                         "%s: the store's `current` names %s and no such version "
                         "directory exists" % (label, d["current"]),
                         "FORMAT-0.1 §9.2: a failed or interrupted operation "
                         "MUST leave either the previous valid state or the new "
                         "one, never a mixture")
        if (not o.installed) and d["current"] and d["current_target_exists"]:
            self.violate("I5-disowned-installation",
                         "%s: `list` does not name the application and the store "
                         "holds a complete installation of %s"
                         % (label, d["current"]),
                         "FORMAT-0.1 §9.2: the set of installed applications "
                         "MUST be mutually consistent with what is stored")
        return d

    # -- filesystem states --------------------------------------------------
    def apply_filesystem(self, which):
        if which == "clean":
            return
        if which == "data-prepopulated":
            # Achieved by RUNNING the application once, which is the only way a
            # package is supposed to acquire data. Fabricating the directory would
            # test the fixture's idea of the layout instead.
            self.cli("run", APP_ID, label="fs:prepopulate-run")
            return
        if which == "stale-cache":
            # A leftover temporary from a previous operation, plus an orphan
            # directory for an application that was never installed. Neither is
            # something the runtime wrote, and neither may change any answer.
            os.makedirs(os.path.join(self.home, "apps", "wl.orphan", "versions",
                                     "9.9.9"), exist_ok=True)
            with open(os.path.join(self.home, "explore-stale.tmp"), "w") as f:
                f.write("left over from an operation that did not finish\n")
            return
        if which == "leftover-lock":
            # docs/CONCURRENCY.md is explicit: "A leftover lock FILE on disk is
            # never, by itself, evidence that anyone holds the lock, and the
            # runtime never deletes a lock file on a staleness heuristic." So this
            # must not produce a busy refusal — asserted, not assumed.
            os.makedirs(os.path.join(self.home, "locks"), exist_ok=True)
            with open(lock_path(self.home, APP_ID), "w") as f:
                f.write("pid 999999 token 0 — a holder that is long gone\n")
            return
        raise AssertionError("unknown filesystem state %r" % which)

    # -- concurrency conditions ---------------------------------------------
    def start_pressure(self, which, cfg):
        if which == "cpu-pressure":
            n = max(2, (os.cpu_count() or 4) // 2)
            for _ in range(n):
                self.pressure.append(subprocess.Popen(
                    [sys.executable, "-c", "\nwhile True: pass\n"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        elif which == "concurrent-reader":
            self.pressure.append(subprocess.Popen(
                ["/bin/sh", "-c",
                 "while :; do %s list --json >/dev/null 2>&1; "
                 "%s info %s --json >/dev/null 2>&1; done"
                 % (cfg.lexe, cfg.lexe, APP_ID)],
                env={"PATH": PINNED_PATH, "LEXE_HOME": self.home},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    # -- damage, the only thing that needs the reference layout --------------
    def damage(self, version, how="modify"):
        p = os.path.join(version_dir(self.home, APP_ID, version), "bin", "prog")
        if not os.path.exists(p):
            return None
        pristine = p + ".pristine"
        shutil.copy2(p, pristine)
        if how == "modify":
            with open(p, "r+b") as f:
                data = bytearray(f.read())
                data[len(data) // 2] ^= 0xFF
                f.seek(0)
                f.write(bytes(data))
        else:
            os.unlink(p)
        return pristine


# --------------------------------------------------------------------------- #
#  TASK 1 — executing one sampled case                                        #
# --------------------------------------------------------------------------- #

UNICODE_ARGS = ["héllo-Ωmega", "日本語", "\U0001f600"]
LONG_ARG = "L" * 4096
AUTHORITY_ENV = {
    "LD_PRELOAD": "",          # filled in with the tattletale library if built
    "LD_LIBRARY_PATH": "/explore-authority-should-not-survive",
    "LD_AUDIT": "/explore-authority-should-not-survive",
}


def build_tattletale(cfg):
    """A shared library whose constructor prints a marker, used to DETECT whether
    LD_PRELOAD survived into the launch.

    FORMAT-0.1 §9.5.2 forbids forwarding any variable that confers authority over
    the launch, and names LD_PRELOAD. That is a statement about behaviour, so it is
    checked behaviourally: if the marker appears from the launched program, the
    variable was forwarded. Reading the runtime's environment-construction code and
    agreeing with it would prove nothing.

    The marker NAMES THE PROCESS THAT PRINTED IT, and that detail is the whole
    check. LD_PRELOAD is set in the environment of `lexe` itself — that is what
    "the caller set it" means — so the library loads into `lexe` too and its
    constructor fires there first. A marker that said only "reached" therefore
    reported on the harness: ten cases were flagged as forwarding when what had
    been observed was `lexe` loading a library its own caller preloaded, which
    §9.5.2 has nothing to say about. Only a marker printed by the PAYLOAD is
    evidence, so the comm name is printed and the payload's is the one looked for.
    """
    out = os.path.join(cfg.scratch, "libtattletale.so")
    if os.path.exists(out):
        return out
    src = os.path.join(cfg.scratch, "tattletale.c")
    with open(src, "w") as f:
        f.write('#include <unistd.h>\n'
                '#include <fcntl.h>\n'
                '#include <string.h>\n'
                '__attribute__((constructor)) static void t(void) {\n'
                '    char comm[64] = {0};\n'
                '    int fd = open("/proc/self/comm", O_RDONLY);\n'
                '    if (fd >= 0) { (void)!read(fd, comm, sizeof comm - 1);'
                ' close(fd); }\n'
                '    for (char *p = comm; *p; ++p) if (*p == 10) *p = 0;\n'
                '    char m[128];\n'
                '    int n = snprintf(m, sizeof m,'
                ' "PRELOAD_REACHED=%s\\n", comm[0] ? comm : "?");\n'
                '    if (n > 0) (void)!write(2, m, (size_t)n);\n'
                '}\n')
        # snprintf needs stdio; kept out of the include list above only by
        # accident would be a compile failure, and a tattletale that fails to
        # build would silently disable the check. It is added here explicitly.
    with open(src) as f:
        body = f.read()
    with open(src, "w") as f:
        f.write("#include <stdio.h>\n" + body)
    for cc in ("cc", "gcc", "clang"):
        if shutil.which(cc, path=PINNED_PATH):
            r = subprocess.run([cc, "-shared", "-fPIC", "-O0", "-o", out, src],
                               capture_output=True, text=True,
                               env={"PATH": PINNED_PATH})
            if r.returncode == 0 and os.path.exists(out):
                return out
    return None


def resolve_dimensions(cfg, corpus):
    """Remove values this host cannot reach, and say which and why.

    A plan that promises pairwise coverage over a chain the host does not have is
    promising coverage of nothing.
    """
    dims = {k: list(v) for k, v in DIMENSIONS.items()}
    gaps = []
    # Chains, from the runtime's own inventory of the HOST (not of itself).
    probe = Cli(cfg.lexe, cfg.scratch)
    _, inv = probe.json_of("runtime", "list", "--json")
    have = set()
    if isinstance(inv, list):
        for row in inv:
            if row.get("available"):
                have.add(row.get("id"))
    elif isinstance(inv, dict):
        for row in inv.get("providers") or inv.get("runtimes") or []:
            if row.get("available"):
                have.add(row.get("id"))
    for extra, needs in (("wine", "wine"), ("proton", "proton")):
        if needs in have and cfg.corpus_pe:
            dims["chain"].append(extra)
        else:
            gaps.append("chain %r not sampled: provider available=%s, PE corpus=%s"
                        % (extra, needs in have, bool(cfg.corpus_pe)))
    if cfg.corpus_pe:
        dims["payload"].append("pe-windows")
    else:
        gaps.append("payload 'pe-windows' not sampled: no PE corpus index given")
    if cfg.corpus_portable:
        dims["payload"].append("portable-tux32")
    else:
        gaps.append("payload 'portable-tux32' not sampled: no portable corpus index")
    # Specimen roles the corpus cannot supply.
    keep = []
    for role in dims["specimen"]:
        if corpus.pick(role) is not None:
            keep.append(role)
        else:
            gaps.append("specimen role %r not sampled: no baseline-ok specimen" % role)
    dims["specimen"] = keep
    return dims, gaps


def run_case(cfg, seed, case):
    """One sampled point. Returns a result record; never raises for a .LEXE fault."""
    cid = case_id(seed, case)
    corpus = cfg.corpus
    spec = corpus.pick(case["specimen"])
    res = {"case_id": cid, "seed": seed, "case": case, "violations": [],
           "skipped": None, "ms": 0.0}
    if spec is None:
        res["skipped"] = "no specimen for role %r" % case["specimen"]
        return res
    if case["payload"] != "native-elf" or case["chain"] != "native":
        # Reached only when the dimension was resolved as available; the engines
        # for foreign chains are against_lexe.py's, not this file's. Recorded so
        # the plan's promise stays honest instead of silently narrowing.
        res["skipped"] = ("payload/chain %s/%s is covered by against_lexe.py, not "
                          "by the sampler" % (case["payload"], case["chain"]))
        return res

    t0 = time.time()
    ws = Workspace(cfg, cid)
    try:
        # ---- arguments
        declared = list(spec.get("argv") or [])
        cli_args, manifest_args = [], []
        if case["arguments"] == "declared":
            manifest_args = declared
        elif case["arguments"] == "extra-unicode":
            manifest_args = declared + UNICODE_ARGS
        elif case["arguments"] == "extra-long":
            manifest_args = declared + [LONG_ARG]
        elif case["arguments"] == "dash-dash-passthrough":
            cli_args = declared or ["--flag"]

        perms = ("network",) if case["sandbox"] == "network-requested" else ()
        pkg = cfg.factory.package(spec, "1.0.0", launch_mode=case["launch_mode"],
                                  args=manifest_args, permissions=perms)
        pkg2 = cfg.factory.package(spec, "2.0.0", launch_mode=case["launch_mode"],
                                   args=manifest_args, permissions=perms)
        if not pkg or not pkg2:
            res["skipped"] = "pack failed for %s" % spec["id"]
            return res

        flags = ["--yes", "--trust"]
        if perms:
            flags.append("--accept-permissions")

        # ---- lifecycle state, reached by real operations
        r = ws.cli("install", pkg, *flags, label="install v1")
        if r["rc"] != 0:
            ws.violate("I0-install", "install of a valid package failed: rc=%d %s"
                       % (r["rc"], (r["err"] or r["out"])[:200]),
                       "FORMAT-0.1 §9.2")
        lc = case["lifecycle"]
        if lc == "after-update":
            ws.cli("install", pkg2, *flags, label="install v2")
        elif lc == "after-rollback":
            ws.cli("install", pkg2, *flags, label="install v2")
            ws.cli("rollback", APP_ID, label="rollback")
        elif lc == "after-repair":
            ws.cli("repair", APP_ID, label="repair")
        elif lc == "after-damage-repair":
            pristine = ws.damage("1.0.0", "modify")
            rd = ws.cli("run", APP_ID, label="run while damaged")
            if rd["rc"] == 0:
                ws.violate("I3-damaged-executed",
                           "a modified installed payload ran and reported success",
                           "FORMAT-0.1 §9.2: it MUST NOT silently be missing files; "
                           "§9.7: compiled content is verified before it is executed")
            rp = ws.cli("repair", APP_ID, label="repair after damage")
            if rp["rc"] == 0 and pristine:
                p = os.path.join(version_dir(ws.home, APP_ID, "1.0.0"), "bin", "prog")
                if os.path.exists(p) and sha256_file(p) != sha256_file(pristine):
                    ws.violate("I3-repair-bytes",
                               "repair reported success without restoring the bytes",
                               "FORMAT-0.1 §9.1: repair it to its VERIFIED content")

        # ---- filesystem state
        ws.apply_filesystem(case["filesystem"])

        # ---- concurrency condition
        ws.start_pressure(case["concurrency"], cfg)

        # ---- the measured launch
        env_over, expect_preload = {}, False
        if case["environment"] == "authority-vars-set":
            over = dict(AUTHORITY_ENV)
            tt = cfg.tattletale
            if tt:
                over["LD_PRELOAD"] = tt
                expect_preload = True
            else:
                over.pop("LD_PRELOAD")
                # Said out loud rather than quietly skipped: without the library
                # this case still exercises LD_LIBRARY_PATH and LD_AUDIT, but the
                # §9.5.2 LD_PRELOAD check is NOT running, and a check that did not
                # run must never read as all-clear.
                ws.violations.append({"id": "GAP-no-tattletale",
                                      "detail": "no C compiler: the §9.5.2 "
                                                "LD_PRELOAD check did not run",
                                      "citation": "FORMAT-0.1 §9.5.2",
                                      "gap": True})
            env_over = over
        elif case["environment"] == "unicode-value":
            env_over = {"LEXE_WORKLOAD_UNICODE": "éΩ日"}
        elif case["environment"] == "no-locale":
            env_over = {"LANG": None, "LC_ALL": None}

        argv = ["run", APP_ID]
        if cli_args:
            argv += ["--"] + cli_args
        timeout = LONG_TIMEOUT_S if case["launch_mode"] == "service" else OP_TIMEOUT_S
        r = ws.cli(*argv, env_overrides=env_over, timeout=timeout,
                   label="measured run")

        # ---- the invariants that do not need to know the right answer
        if case["filesystem"] == "leftover-lock" and r["rc"] == 6:
            ws.violate("I4-stale-lock-file",
                       "a leftover lock FILE (no holder) produced a busy refusal",
                       "docs/CONCURRENCY.md: a leftover lock file on disk is never, "
                       "by itself, evidence that anyone holds the lock")
        # The payload is installed as bin/prog, so its /proc/self/comm is "prog".
        # `lexe` printing the marker is expected and means nothing: the caller put
        # LD_PRELOAD in lexe's environment. Only the PAYLOAD printing it is a
        # forwarding of authority into the launch.
        reached = [l.split("=", 1)[1].strip()
                   for l in (r["out"] + r["err"]).splitlines()
                   if l.startswith("PRELOAD_REACHED=")]
        if expect_preload and any(c == "prog" for c in reached):
            ws.violate("I5-authority-env-forwarded",
                       "LD_PRELOAD set by the CALLER reached the launched payload "
                       "(markers from: %s)" % ", ".join(sorted(set(reached))),
                       "FORMAT-0.1 §9.5.2: a runtime MUST NOT forward any variable "
                       "that confers authority over the launch — LD_PRELOAD and "
                       "LD_LIBRARY_PATH and their equivalents")
        # Oracle fidelity, only where no dimension legitimately changes the output.
        if (case["arguments"] in ("none", "declared")
                and case["environment"] == "minimal"
                and case["launch_mode"] == "console"
                and case["specimen"] in ("plain", "alt")
                and case["lifecycle"] != "after-damage-repair"):
            want = corpus.baseline_exit(spec)
            if want is not None and r["rc"] != want and not r["timed_out"]:
                ws.violate("I6-oracle-exit",
                           "specimen %s exits %s directly and %s through .LEXE"
                           % (spec["id"], want, r["rc"]),
                           "the specimen's direct-execution baseline is the oracle")

        ws.check_all_records()
        ws.check_coherent("end of case")
        res["violations"] = ws.violations
        res["ops"] = [{"op": j["op"], "rc": j["rc"], "ms": j["ms"]}
                      for j in ws.cli.journal]
        res["timings"] = {j["op"]: j["ms"] for j in ws.cli.journal}
    finally:
        ws.close()
        res["ms"] = round((time.time() - t0) * 1000.0, 1)
    return res


# --------------------------------------------------------------------------- #
#  TASK 2 — executing sequences against the model                             #
# --------------------------------------------------------------------------- #

# Ops the random walk may emit, and how each becomes a command line. `stop` is
# absent because there is no such verb; it is checked once, on its own, and
# reported as STOP_GAP rather than pretended into the walk.
WALK_OPS = ("verify", "install", "install_newer", "install_same",
            "install_older", "install_other_key", "run", "update", "rollback",
            "repair", "doctor", "doctor_repair", "uninstall", "uninstall_purge")

# Fixture actions. Not operations of the runtime, so they carry no expectation:
# they are how a sequence REACHES a state the runtime has no verb for.
FIXTURE_ACTIONS = ("damage_modify", "damage_delete")

VERSIONS = ["1.0.0", "2.0.0", "3.0.0"]


class SequenceRunner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.pkgs = {}
        plain = cfg.corpus.pick("plain")
        alt = cfg.corpus.pick("alt") or plain
        self.spec_for = {"1.0.0": plain, "2.0.0": alt, "3.0.0": plain}
        for v in VERSIONS:
            self.pkgs[("main", v)] = cfg.factory.package(self.spec_for[v], v)
        self.pkgs[("other", "1.0.0")] = cfg.factory.package(plain, "1.0.0",
                                                            key="other")

    def legal_ops(self, s):
        """Which ops the walk may emit here. Not which ops are LEGAL — the whole
        point is to emit illegal ones — only which are well-formed given the
        version ladder."""
        ops = list(WALK_OPS)
        if s.present and s.active == VERSIONS[-1]:
            ops.remove("install_newer")
        if not s.present:
            for o in ("install_newer", "install_same", "install_older"):
                if o in ops:
                    ops.remove(o)
        return ops

    def argv_for(self, op, s):
        if op == "verify":
            return ["verify", self.pkgs[("main", "1.0.0")]]
        if op == "install":
            return ["install", self.pkgs[("main", "1.0.0")], "--yes", "--trust"]
        if op == "install_newer":
            nxt = VERSIONS[VERSIONS.index(s.active) + 1]
            return ["install", self.pkgs[("main", nxt)], "--yes", "--trust"]
        if op == "install_same":
            return ["install", self.pkgs[("main", s.active)], "--yes", "--trust"]
        if op == "install_older":
            lower = VERSIONS[max(0, VERSIONS.index(s.active) - 1)]
            return ["install", self.pkgs[("main", lower)], "--yes", "--trust"]
        if op == "install_other_key":
            return ["install", self.pkgs[("other", "1.0.0")], "--yes", "--trust"]
        if op == "run":
            return ["run", APP_ID]
        if op == "update":
            return ["update", APP_ID]
        if op == "rollback":
            return ["rollback", APP_ID]
        if op == "repair":
            return ["repair", APP_ID]
        if op == "doctor":
            return ["doctor"]
        if op == "doctor_repair":
            return ["doctor", "--repair"]
        if op == "uninstall":
            return ["remove", APP_ID, "--yes"]
        if op == "uninstall_purge":
            return ["remove", APP_ID, "--purge-data", "--yes"]
        raise AssertionError(op)

    def run_sequence(self, seed, idx, length, illegal_bias):
        rng = random.Random("seq|%s|%d" % (seed, idx))
        s = Abstract()
        ws = Workspace(self.cfg, "seq%d" % idx)
        trace = {"seed": seed, "index": idx, "start_state": s.name(),
                 "fixture": {v: self.spec_for[v]["id"] for v in VERSIONS},
                 "ops": [], "divergences": [], "underspec": [],
                 "kinds": {PIN: 0, ANY_REFUSE: 0, UNDERSPEC: 0},
                 "illegal_bias": illegal_bias}
        try:
            for step in range(length):
                pool = self.legal_ops(s)
                if rng.random() < 0.12:
                    act = rng.choice(FIXTURE_ACTIONS)
                    if s.present and s.health_of() == "OK":
                        self._apply_fixture(ws, s, act)
                        trace["ops"].append({"op": act, "fixture": True})
                    continue
                if illegal_bias and rng.random() < illegal_bias:
                    # Prefer an op the model says must be refused here. That is
                    # where the findings are: an operation that should be refused
                    # and is not, or is refused with the wrong code.
                    refused = [o for o in pool
                               if Model.expect(s, o)[0] != PIN
                               or 0 not in Model.expect(s, o)[1]]
                    pool = refused or pool
                op = rng.choice(pool)
                kind, codes, nxt, why = Model.expect(s, op)
                rec = ws.cli(*self.argv_for(op, s), label=op)
                got = outcome_class(rec)
                entry = {"op": op, "rc": rec["rc"], "class": got,
                         "model_state": s.name(), "kind": kind, "ms": rec["ms"]}
                trace["kinds"][kind] = trace["kinds"].get(kind, 0) + 1
                bad = crashed(rec)
                if bad:
                    trace["divergences"].append(
                        {"kind": "CRASH", "op": op, "state": s.name(),
                         "detail": bad, "citation":
                         "docs/ERRORS.md §1 enumerates every exit a caller may see",
                         "step": step})
                if kind == PIN and rec["rc"] not in codes and not rec["timed_out"]:
                    trace["divergences"].append(
                        {"kind": "PINNED", "op": op, "state": s.name(),
                         "expected": sorted(codes), "got": rec["rc"],
                         "citation": why, "step": step,
                         "message": (rec["err"] or rec["out"]).strip()[:200]})
                elif kind == ANY_REFUSE and rec["rc"] == 0:
                    trace["divergences"].append(
                        {"kind": "SHOULD-REFUSE", "op": op, "state": s.name(),
                         "expected": "any non-zero", "got": 0,
                         "citation": why, "step": step})
                elif kind == UNDERSPEC:
                    trace["underspec"].append(
                        {"key": list(s.key()), "op": op, "class": got,
                         "rc": rec["rc"], "citation": why})
                # The model only advances on an operation that succeeded; a
                # refusal, by definition, did not change the state.
                if rec["rc"] == 0:
                    s = nxt
                trace["ops"].append(entry)

            o = observe(ws.cli, APP_ID)
            self._compare_state(trace, s, o)
            ws.check_all_records()
            for v in ws.violations:
                trace["divergences"].append({"kind": "INVARIANT", **v})
            trace["final_model"] = s.name()
            trace["final_observed"] = o.state_name()
        finally:
            ws.close()
        return trace

    def run_explicit(self, ops, spec_map):
        """Replay a GIVEN operation list. The minimiser's only executor.

        Deliberately shares `Model` and the comparison code with `run_sequence`,
        so a minimised reproducer is judged by exactly the same rules that first
        reported the failure. A reducer with its own idea of what failure means
        reduces to its own idea of the bug.
        """
        s = Abstract()
        ws = Workspace(self.cfg, "replay")
        trace = {"seed": "explicit", "index": -1, "start_state": s.name(),
                 "fixture": dict(spec_map or
                                 {v: self.spec_for[v]["id"] for v in VERSIONS}),
                 "ops": [], "divergences": [], "underspec": [], "explicit": True}
        try:
            for step, op in enumerate(ops):
                if op in FIXTURE_ACTIONS:
                    if s.present and s.health_of() == "OK":
                        self._apply_fixture(ws, s, op)
                    trace["ops"].append({"op": op, "fixture": True})
                    continue
                if op not in self.legal_ops(s):
                    # The op is not well-formed at this point in the shortened
                    # sequence (no active version to name, say). Skipping it
                    # rather than failing keeps ddmin honest: a candidate that
                    # cannot be expressed is simply a candidate that does not
                    # reproduce.
                    trace["ops"].append({"op": op, "skipped": "ill-formed here"})
                    continue
                kind, codes, nxt, why = Model.expect(s, op)
                rec = ws.cli(*self.argv_for(op, s), label=op)
                got = outcome_class(rec)
                trace["ops"].append({"op": op, "rc": rec["rc"], "class": got,
                                     "model_state": s.name(), "kind": kind,
                                     "ms": rec["ms"]})
                bad = crashed(rec)
                if bad:
                    trace["divergences"].append(
                        {"kind": "CRASH", "op": op, "state": s.name(),
                         "detail": bad, "step": step})
                if kind == PIN and rec["rc"] not in codes and not rec["timed_out"]:
                    trace["divergences"].append(
                        {"kind": "PINNED", "op": op, "state": s.name(),
                         "expected": sorted(codes), "got": rec["rc"],
                         "citation": why, "step": step,
                         "message": (rec["err"] or rec["out"]).strip()[:200]})
                elif kind == ANY_REFUSE and rec["rc"] == 0:
                    trace["divergences"].append(
                        {"kind": "SHOULD-REFUSE", "op": op, "state": s.name(),
                         "expected": "any non-zero", "got": 0,
                         "citation": why, "step": step})
                elif kind == UNDERSPEC:
                    trace["underspec"].append({"key": list(s.key()), "op": op,
                                               "class": got, "rc": rec["rc"],
                                               "citation": why})
                if rec["rc"] == 0:
                    s = nxt
            o = observe(ws.cli, APP_ID)
            self._compare_state(trace, s, o)
            ws.check_all_records()
            for v in ws.violations:
                trace["divergences"].append({"kind": "INVARIANT", **v})
            trace["final_model"] = s.name()
            trace["final_observed"] = o.state_name()
        finally:
            ws.close()
        return trace

    def _apply_fixture(self, ws, s, act):
        if not s.present or not s.active:
            return
        how = "modify" if act == "damage_modify" else "delete"
        if ws.damage(s.active, how) is not None:
            s.damaged[s.active] = "MODIFIED" if how == "modify" else "MISSING"

    def _compare_state(self, trace, s, o):
        """Model vs the outside. Only properties the documents make observable.

        The retained-version SET is deliberately not compared: retention beyond
        the active version and its rollback target is a policy the format does not
        fix (§9.1 requires only that two versions CAN coexist), so a mismatch
        there would be the model being opinionated, not the runtime being wrong.
        """
        if s.present != o.installed:
            trace["divergences"].append(
                {"kind": "STATE", "field": "present", "expected": s.present,
                 "got": o.installed,
                 "citation": "FORMAT-0.1 §9.2: installed applications and their "
                             "active versions MUST be mutually consistent"})
        if s.present and o.installed and s.active != o.active:
            trace["divergences"].append(
                {"kind": "STATE", "field": "active", "expected": s.active,
                 "got": o.active,
                 "citation": "FORMAT-0.1 §9.1: an installed version is identified "
                             "by (App ID, version string)"})
        if s.present and o.installed and s.health_of() == "OK" and o.launchable is False:
            trace["divergences"].append(
                {"kind": "STATE", "field": "launchable", "expected": True,
                 "got": False, "observed_class": o.run_class,
                 "citation": "FORMAT-0.1 §9.2: an application that reports as "
                             "installed MUST be launchable"})
        if s.present and o.installed and s.health_of() != "OK" and o.launchable is True:
            trace["divergences"].append(
                {"kind": "STATE", "field": "damaged-but-ran", "expected": False,
                 "got": True,
                 "citation": "FORMAT-0.1 §9.2: it MUST NOT silently be missing "
                             "files; §9.7: content is verified before execution"})


def run_permission_scenarios(cfg):
    """The §9.5.1 / §9.5 pins, executed once each against a fresh home."""
    out = []
    plain = cfg.corpus.pick("plain")
    for sc in PERMISSION_SCENARIOS:
        ws = Workspace(cfg, "perm")
        row = {"id": sc["id"], "why": sc["why"], "steps": [], "ok": True}
        try:
            for (op, kw, want) in sc["steps"]:
                if op == "install":
                    pkg = cfg.factory.package(
                        plain, kw.get("version", "1.0.0"),
                        key=kw.get("key", "main"),
                        permissions=kw.get("perms", ()))
                    if not pkg:
                        row["ok"] = None
                        row["steps"].append({"op": op, "skipped": "pack failed"})
                        break
                    rec = ws.cli("install", pkg, *kw.get("flags", ("--yes",)),
                                 label=op)
                elif op == "run":
                    rec = ws.cli("run", APP_ID, label=op)
                elif op == "rollback":
                    rec = ws.cli("rollback", APP_ID, label=op)
                elif op == "remove":
                    rec = ws.cli("remove", APP_ID, "--yes", label=op)
                elif op == "remove_purge":
                    rec = ws.cli("remove", APP_ID, "--purge-data", "--yes",
                                 label=op)
                else:
                    raise AssertionError(op)
                good = rec["rc"] in want
                row["steps"].append(
                    {"op": op, "kw": {k: list(v) if isinstance(v, tuple) else v
                                      for k, v in kw.items()},
                     "want": sorted(want), "rc": rec["rc"], "ok": good,
                     "message": (rec["err"] or rec["out"]).strip()[:200]})
                if not good:
                    row["ok"] = False
                    break
        finally:
            ws.close()
        out.append(row)
    return out


# Two refusals that are correct in prose and lossy in the exit code. Neither is a
# behavioural defect: .LEXE refuses the right thing and explains it well. What is
# lost is the MACHINE-READABLE half, which docs/ERRORS.md exists to provide, and
# docs/ERRORS.md §1.1 makes exactly this argument for keeping 3 and 7 apart:
# "collapsing them would hide the more alarming one inside the more common one".
#
# They are recorded as OBSERVATIONS and never as failures. The documents do not
# decide which code belongs to either condition, and inventing a verdict here
# would turn an open question into a red lane — or, worse, into a test that has
# to be rewritten the moment somebody answers it.
TAXONOMY_QUESTIONS = [
    {
        "id": "already-current-install-is-the-untyped-1",
        "question": ("`lexe install` of the version that is ALREADY current exits "
                     "1 — the catch-all docs/ERRORS.md §1 describes as \"the "
                     "operation failed for a reason with no more specific code\". "
                     "The condition is specific, benign and has its own remedy "
                     "(`lexe repair`), and §1 already has a code for exactly this "
                     "shape: 6, \"busy, or an OPERATION CONFLICT\". A script that "
                     "re-runs an installer idempotently, or races two of them, "
                     "cannot tell this apart from a real failure. Seen in 22 of 32 "
                     "install||install races and reproducible in one command."),
    },
    {
        "id": "rollback-with-no-target-is-indistinguishable-from-a-typo",
        "question": ("`lexe rollback <installed app with no previous version>` and "
                     "`lexe rollback <no such app>` both exit 4. The prose differs "
                     "and is good; the exit code does not. docs/ERRORS.md §2 says "
                     "NotFoundError means \"no such application, file or entry\" "
                     "and that \"a mistyped path lands here too\" — so a caller "
                     "reading 4 must conclude the App ID is wrong, which here it "
                     "is not. The remedies are unrelated: fix the id, versus there "
                     "is nothing to roll back to."),
    },
]


def check_taxonomy(cfg):
    """Run both conditions and record what a CALLING SCRIPT actually sees."""
    out = []
    plain = cfg.corpus.pick("plain")
    pkg = cfg.factory.package(plain, "1.0.0")
    ws = Workspace(cfg, "tax")
    try:
        if not pkg:
            return [{"id": q["id"], "skipped": "pack failed"}
                    for q in TAXONOMY_QUESTIONS]
        ws.cli("install", pkg, "--yes", "--trust", label="install")
        again = ws.cli("install", pkg, "--yes", "--trust", label="install again")
        junk = os.path.join(ws.dir, "junk.lexe")
        with open(junk, "wb") as f:
            f.write(os.urandom(300))
        broken = ws.cli("install", junk, "--yes", "--trust", label="install junk")
        out.append({**TAXONOMY_QUESTIONS[0],
                    "already_current_rc": again["rc"],
                    "genuinely_broken_package_rc": broken["rc"],
                    "message": (again["err"] or again["out"]).strip()[:200]})
        no_target = ws.cli("rollback", APP_ID, label="rollback no target")
        no_app = ws.cli("rollback", "no.such.app.at.all", label="rollback no app")
        out.append({**TAXONOMY_QUESTIONS[1],
                    "no_rollback_target_rc": no_target["rc"],
                    "no_such_application_rc": no_app["rc"],
                    "indistinguishable": no_target["rc"] == no_app["rc"],
                    "message": (no_target["err"] or no_target["out"]).strip()[:200]})
    finally:
        ws.close()
    return out


def check_stop_verb(cfg):
    """`stop` is in the lifecycle operation set and not in the CLI.

    Executed rather than asserted from the help text: an undocumented verb that
    happened to work would make the gap a documentation problem instead of a
    missing capability, and those need different answers.
    """
    ws = Workspace(cfg, "stop")
    try:
        rec = ws.cli("stop", APP_ID, label="stop")
        return {"rc": rec["rc"], "class": outcome_class(rec),
                "message": (rec["err"] or rec["out"]).strip()[:300],
                "gap": STOP_GAP}
    finally:
        ws.close()


def check_doctor_convergence(cfg, rounds=3):
    """`doctor --repair` must CONVERGE, whatever its exit code means.

    The exit code is undocumented (DOCTOR_GAP), so this asserts the property that
    needs no document: after a repair pass, either the machine reports healthy or
    it names what it could not repair. A doctor that reports problems, repairs
    nothing, lists nothing as unrepaired and exits 0 is a gate that cannot gate.
    """
    ws = Workspace(cfg, "doctor")
    out = {"rounds": [], "gap": DOCTOR_GAP, "converged": None,
           "reports_problems_with_exit_zero": None}
    try:
        plain = cfg.corpus.pick("plain")
        pkg = cfg.factory.package(plain, "1.0.0")
        if pkg:
            ws.cli("install", pkg, "--yes", "--trust", label="install")
        for i in range(rounds):
            r0, before = ws.cli.json_of("doctor", "--json", label="doctor")
            rr = ws.cli("doctor", "--repair", label="doctor --repair")
            r1, after = ws.cli.json_of("doctor", "--json", label="doctor")
            row = {"round": i,
                   "before": {"rc": r0["rc"],
                              "ok": (before or {}).get("ok"),
                              "problems": (before or {}).get("problems")},
                   "repair_rc": rr["rc"],
                   "after": {"rc": r1["rc"], "ok": (after or {}).get("ok"),
                             "problems": (after or {}).get("problems"),
                             "repaired": len((after or {}).get("repaired") or []),
                             "unrepaired": len((after or {}).get("unrepaired") or [])}}
            out["rounds"].append(row)
            if i == 0 and before:
                out["reports_problems_with_exit_zero"] = (
                    before.get("ok") is False and (before.get("problems") or 0) > 0
                    and r0["rc"] == 0)
            if after:
                out["converged"] = bool(after.get("ok")) or \
                    len(after.get("unrepaired") or []) > 0
    finally:
        ws.close()
    return out


# --------------------------------------------------------------------------- #
#  TASK 4 — generated concurrent schedules                                    #
# --------------------------------------------------------------------------- #
#
# Two ways to enter a contended window, and the difference is the whole point:
#
#   "barrier"  both participants spin on a file and are released together. Real,
#              but probabilistic: the mutation lock is held for ~20ms, so whether
#              B arrives inside A's critical section is luck, bought with repeats.
#
#   "trigger"  A is made to hold its critical section for a LONG time by choosing
#              a payload that runs for a known interval, and B is started only
#              once the externally visible artefact of that hold exists (the
#              launch lease file, docs/CONCURRENCY.md). B is then guaranteed to
#              arrive inside the window. This is forcing, not luck, and it needs
#              no hook in production code.
#
#   "hold"     the interleavings "trigger" cannot reach are the ones inside a
#              SHORT mutation's critical section — install vs install, repair vs
#              repair, update vs rollback. Those needed a hold point the process
#              will honour, and one now exists: LEXE_TEST_HOLD_APPLOCK_MS, read
#              once, inert when unset, honoured after the per-app mutation lock
#              is acquired. A is started with it set; B is released only once the
#              hold is WITNESSED, and the witness is two observations that do not
#              fail for the same reason (see _await_applock).
#
# What none of the three reach is an interleaving inside an operation that takes
# no per-app lock at all, and that is stated rather than papered over.

SCHEDULES = [
    # (id, mode, setup, A, B, oracle)
    ("run||update", "trigger", "installed-long", ["run", APP_ID],
     ["install", "@v2", "--yes", "--trust"], "running-undisturbed"),
    ("uninstall||run", "trigger", "installed-long",
     ["run", APP_ID], ["remove", APP_ID, "--yes"], "uninstall-refused-while-running"),
    ("gc||run", "trigger", "installed-long-two-versions",
     ["run", APP_ID], ["gc", APP_ID, "--keep", "0"], "running-files-survive"),
    ("rollback||run", "trigger", "installed-long-two-versions",
     ["run", APP_ID], ["rollback", APP_ID], "running-undisturbed"),
    ("repair||run", "trigger", "installed-long", ["run", APP_ID],
     ["repair", APP_ID], "running-undisturbed"),
    ("install||install", "hold", "absent",
     ["install", "@v1", "--yes", "--trust"],
     ["install", "@v1", "--yes", "--trust"], "one-coherent-installation"),
    ("repair||repair", "hold", "installed",
     ["repair", APP_ID], ["repair", APP_ID], "healthy-afterwards"),
    ("update||rollback", "hold", "installed-two-versions",
     ["install", "@v3", "--yes", "--trust"], ["rollback", APP_ID],
     "coherent-and-the-program-matches-the-record"),
    ("uninstall||uninstall", "hold", "installed",
     ["remove", APP_ID, "--yes"], ["remove", APP_ID, "--yes"], "absent-afterwards"),
    ("doctor-repair||uninstall", "barrier", "installed",
     ["doctor", "--repair"], ["remove", APP_ID, "--yes"], "absent-afterwards"),
    ("update||repair", "hold", "installed",
     ["install", "@v2", "--yes", "--trust"], ["repair", APP_ID],
     "healthy-afterwards"),
    ("service-start||update", "barrier", "installed-service",
     ["run", APP_ID], ["install", "@v2", "--yes", "--trust"],
     "coherent-and-the-program-matches-the-record"),
    ("uninstall||repair", "hold", "installed",
     ["remove", APP_ID, "--yes"], ["repair", APP_ID], "coherent"),
    ("rollback||rollback", "hold", "installed-two-versions",
     ["rollback", APP_ID], ["rollback", APP_ID], "coherent"),
    # The promote is the instant installed state changes. A reader that takes no
    # per-app mutation lock can observe it, so widening it with
    # LEXE_TEST_HOLD_BEFORE_COMMIT_MS asks the question the mutation locks cannot:
    # can anything see a torn state? docs/CONCURRENCY.md: "activation (the
    # `current` flip) is atomic, so a launch never sees a torn mix."
    ("update||run-observer", "hold-commit", "installed",
     ["install", "@v2", "--yes", "--trust"], ["run", APP_ID],
     "observer-saw-one-whole-version"),
    ("update||info-observer", "hold-commit", "installed",
     ["install", "@v2", "--yes", "--trust"], ["info", APP_ID],
     "observer-saw-one-whole-version"),
    # Deliberately "hold" and not "hold-commit". Measured, five samples each:
    # LEXE_TEST_HOLD_BEFORE_COMMIT_MS widens install/update (0.015s -> 3.014s)
    # and does NOTHING for rollback (0.004s), repair (0.011s) or remove
    # (0.005s) — they do not promote through InstallTransaction. So a rollback's
    # promote window cannot be widened from outside; its MUTATION window can,
    # and that is what this schedule forces. Stated rather than silently
    # downgraded, because a hold that is inert looks exactly like a race that
    # never happens.
    ("rollback||run-observer", "hold", "installed-two-versions",
     ["rollback", APP_ID], ["run", APP_ID],
     "observer-saw-one-whole-version"),
]

# The spin-and-go barrier, as a real script with a real shebang. The shebang is
# not boilerplate: without it execve gave ENOEXEC, every barrier-mode schedule
# raised OSError(8) in its worker, and a race campaign reported "120 runs, 0
# violations" for the five TRIGGER schedules while the nine BARRIER schedules —
# install||install, repair||repair, update||rollback among them — had silently not
# run at all. A campaign that reports a count for the half that executed is worse
# than one that fails outright.
BARRIER_SH = (
    '#!/bin/sh\n'
    'while [ ! -e "$1" ]; do :; done\n'
    'shift\n'
    'exec "$@"\n'
)


class RaceRunner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.plain = cfg.corpus.pick("plain")
        self.alt = cfg.corpus.pick("alt") or self.plain
        self.long = cfg.corpus.pick("long")
        # How to tell the two subject programs apart AFTER a race, derived from
        # their own baselines rather than asserted.
        #
        # The obvious marker is wrong, and it cost this engine sixteen false
        # violations. `FIXTURE_ID` is set by the corpus generator IN THE
        # ENVIRONMENT; the specimen echoes it and falls back to a compiled-in
        # short name when it is absent. FORMAT-0.1 §9.5.2 requires a runtime to
        # reset the environment to a defined set, so under .LEXE the variable is
        # correctly gone and every specimen reports its fallback name. Comparing
        # against the corpus id then says "the record claims 3.0.0 but the program
        # is linux-outcome-exit, not linux-outcome-exit-0" — a disagreement
        # manufactured entirely by the harness, on top of behaviour that is
        # exactly right.
        #
        # So identity is taken from keys the two specimens do not SHARE, which is
        # what against_lexe_lifecycle.sh does for the same reason. If the corpus
        # ever supplies two specimens with identical key sets, there is no marker
        # and the check says so instead of guessing.
        self.marks = {}
        if self.plain and self.alt and self.plain["id"] != self.alt["id"]:
            pk = set(cfg.corpus.baseline_keys(self.plain))
            ak = set(cfg.corpus.baseline_keys(self.alt))
            only_p, only_a = sorted(pk - ak), sorted(ak - pk)
            if only_p and only_a:
                self.marks = {"plain": only_p[0], "alt": only_a[0]}
        self.barrier = os.path.join(cfg.scratch, "barrier.sh")
        with open(self.barrier, "w") as f:
            f.write(BARRIER_SH)
        os.chmod(self.barrier, 0o755)

    def _packages(self, setup):
        f = self.cfg.factory
        if "long" in setup and self.long:
            # A payload that runs for a known interval, so the launch lease — the
            # externally visible fact that a version is in use — is held long
            # enough for the other participant to be forced into the window.
            hold = str(self.cfg.hold_ms)
            v1 = f.package(self.long, "1.0.0", args=[hold])
            v2 = f.package(self.long, "2.0.0", args=[hold])
            v3 = f.package(self.long, "3.0.0", args=[hold])
        elif "service" in setup:
            v1 = f.package(self.plain, "1.0.0", launch_mode="service")
            v2 = f.package(self.alt, "2.0.0", launch_mode="service")
            v3 = f.package(self.plain, "3.0.0", launch_mode="service")
        else:
            v1 = f.package(self.plain, "1.0.0")
            v2 = f.package(self.alt, "2.0.0")
            v3 = f.package(self.plain, "3.0.0")
        return {"@v1": v1, "@v2": v2, "@v3": v3}

    def run(self, sched, rep, pressure):
        sid, mode, setup, a, b, oracle = sched
        ws = Workspace(self.cfg, "race")
        row = {"schedule": sid, "mode": mode, "rep": rep, "setup": setup,
               "pressure": pressure, "violations": [], "a": None, "b": None}
        try:
            pk = self._packages(setup)
            if not all(pk.values()):
                row["skipped"] = "pack failed"
                return row
            if setup != "absent":
                ws.cli("install", pk["@v1"], "--yes", "--trust", label="setup v1")
            if "two-versions" in setup:
                ws.cli("install", pk["@v2"], "--yes", "--trust", label="setup v2")
            if pressure:
                ws.start_pressure("cpu-pressure", self.cfg)

            subst = lambda v: pk.get(v, v)
            argv_a = [self.cfg.lexe] + [subst(x) for x in a]
            argv_b = [self.cfg.lexe] + [subst(x) for x in b]
            env = ws.cli.env()

            if mode == "trigger":
                # Start A, wait for the externally visible artefact of its hold,
                # then release B. If the artefact never appears the schedule is
                # reported as NOT FORCED rather than silently downgraded to luck.
                pa = subprocess.Popen(argv_a, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, env=env,
                                      cwd=ws.home)
                forced = self._await_lease(ws.home, deadline=10.0)
                row["forced"] = forced
                pb = subprocess.Popen(argv_b, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, env=env,
                                      cwd=ws.home)
            elif mode in ("hold", "hold-commit"):
                # A is asked to hold the window open; B is released only once the
                # hold is WITNESSED from outside. A witness that does not fire is
                # reported as NOT FORCED — the run still executes and is still
                # checked, it is simply not counted as a forced interleaving.
                var = ("LEXE_TEST_HOLD_APPLOCK_MS" if mode == "hold"
                       else "LEXE_TEST_HOLD_BEFORE_COMMIT_MS")
                held_ms = (self.cfg.applock_hold_ms if mode == "hold"
                           else self.cfg.commit_hold_ms)
                env_a = dict(env)
                env_a[var] = str(held_ms)
                pa = subprocess.Popen(argv_a, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True,
                                      env=env_a, cwd=ws.home)
                if mode == "hold":
                    forced, why = self._await_applock(
                        ws.home, pa.pid, deadline=min(held_ms / 1000.0, 15.0))
                else:
                    # The commit hold is INSIDE the mutation lock, so the same
                    # two witnesses see it; what differs is which window B lands
                    # in, because the promote has not happened yet.
                    forced, why = self._await_applock(
                        ws.home, pa.pid, deadline=min(held_ms / 1000.0, 15.0))
                row["forced"] = forced
                row["force_mechanism"] = "%s=%d" % (var, held_ms)
                row["force_witness"] = why
                pb = subprocess.Popen(argv_b, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, env=env,
                                      cwd=ws.home)
            else:
                go = os.path.join(ws.dir, "go")
                pa = subprocess.Popen([self.barrier, go] + argv_a,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, env=env, cwd=ws.home)
                pb = subprocess.Popen([self.barrier, go] + argv_b,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, env=env, cwd=ws.home)
                time.sleep(0.25)
                open(go, "w").close()
                row["forced"] = False

            recs = []
            for tag, p in (("a", pa), ("b", pb)):
                try:
                    out, err = p.communicate(timeout=LONG_TIMEOUT_S)
                    rec = {"op": tag, "rc": p.returncode, "ms": 0,
                           "timed_out": False, "out": out or "", "err": err or ""}
                except subprocess.TimeoutExpired:
                    p.kill()
                    out, err = p.communicate()
                    rec = {"op": tag, "rc": -1, "ms": 0, "timed_out": True,
                           "out": out or "", "err": err or ""}
                recs.append(rec)
                row[tag] = {"rc": rec["rc"], "class": outcome_class(rec),
                            "timed_out": rec["timed_out"],
                            "out": rec["out"][:400], "err": rec["err"][:400]}
                bad = crashed(rec)
                if bad:
                    ws.violate("R1-no-crash-or-hang", "%s (%s): %s" % (sid, tag, bad),
                               "a deadlock or an abort under contention is a defect "
                               "whichever participant wins")
            self._oracle(ws, row, oracle, recs, pk)
            ws.check_all_records()
            row["violations"] = ws.violations
        finally:
            ws.close()
        return row

    @staticmethod
    def _await_applock(home, pid_a, deadline):
        """Wait until participant A is INSIDE its per-app mutation critical
        section, and require two observations that do not fail for the same
        reason before calling the window forced.

        Observation 1 — `flock(LOCK_EX|LOCK_NB)` on `locks/<id>.lock` is
        REFUSED. This is the kernel's answer and cannot be faked by a leftover
        file, which is the trap docs/CONCURRENCY.md warns about ("a leftover
        lock file on disk is never, by itself, evidence that anyone holds the
        lock"). It can still be satisfied by the WRONG holder — a straggler from
        a previous repetition, or this harness's own probe.

        Observation 2 — the owner record the holder writes into the lock file
        (`pid=… start=… op=… at=…`) names pid_a, and that pid is alive. This
        reads a different mechanism written by different code, so it does not
        fail for the same reason: a stale record survives the writer, and an
        unwritten one is invisible to flock.

        Neither alone is enough. Observation 1 alone once let a previous
        repetition's holder be mistaken for this one; observation 2 alone would
        accept a record written and then released microseconds later. Returns
        (forced, why) and `why` names which observation refused, so a campaign
        with a low forced ratio says WHERE it lost the window instead of
        reporting the ratio and nothing else.
        """
        lockf = os.path.join(home, "locks", APP_ID + ".lock")
        end = time.time() + max(deadline, 0.5)
        saw_flock = saw_owner = False
        while time.time() < end:
            if os.path.exists(lockf):
                try:
                    fd = os.open(lockf, os.O_RDWR)
                except OSError:
                    time.sleep(0.002)
                    continue
                refused = False
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    refused = True
                os.close(fd)
                if refused:
                    saw_flock = True
                    try:
                        with open(lockf, "rb") as f:
                            line = f.read(512).decode("utf-8", "replace")
                    except OSError:
                        line = ""
                    owner_pid = None
                    for tok in line.split():
                        if tok.startswith("pid="):
                            try:
                                owner_pid = int(tok[4:])
                            except ValueError:
                                owner_pid = None
                    if owner_pid == pid_a and os.path.isdir("/proc/%d" % pid_a):
                        saw_owner = True
                        return True, "flock refused and owner record names pid %d" % pid_a
            time.sleep(0.002)
        if not saw_flock:
            return False, "the mutation lock was never observed held"
        if not saw_owner:
            return False, ("the lock was held but its owner record never named "
                           "pid %d" % pid_a)
        return False, "unreached"

    @staticmethod
    def _await_lease(home, deadline):
        """Wait until a launch lease is HELD — not until its file exists.

        docs/CONCURRENCY.md: "A leftover lock file on disk is never, by itself,
        evidence that anyone holds the lock." Another check in this file quotes
        that sentence, and this trigger broke it anyway. Waiting for the FILE
        released the second participant during the launcher's resolve->lease
        window; the launcher then lost the race and failed closed with "current
        version directory is missing", which the TOCTOU section of that same
        document describes as the correct outcome. One run in 24 was reported as a
        §9.4 violation for doing exactly what it is supposed to do.

        `flock(LOCK_EX|LOCK_NB)` answers the real question. If an exclusive
        acquisition is REFUSED, someone holds the lease. If it succeeds, nobody
        does — and it is released again immediately, so the probe cannot become
        the thing that blocks the launch it is waiting for.
        """
        locks = os.path.join(home, "locks")
        end = time.time() + deadline
        while time.time() < end:
            try:
                names = [n for n in os.listdir(locks) if n.endswith(".lease")]
            except OSError:
                names = []
            for n in names:
                try:
                    fd = os.open(os.path.join(locks, n), os.O_RDWR)
                except OSError:
                    continue
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    os.close(fd)
                    return True          # refused: a holder exists
                os.close(fd)
            time.sleep(0.002)
        return False

    def _oracle(self, ws, row, oracle, recs, pk):
        a, b = recs
        # The documented TOCTOU outcome, separated from a violation. A launch
        # that lost the resolve->lease race fails CLOSED with a stated reason and
        # never execs; docs/CONCURRENCY.md says so explicitly. It is counted and
        # reported, because a trigger that produces it often is a weak trigger,
        # but it is not the runtime misbehaving.
        FAILED_CLOSED = "version directory of"
        row["launch_failed_closed"] = (FAILED_CLOSED in (a["err"] or ""))
        if oracle == "uninstall-refused-while-running":
            if row["launch_failed_closed"]:
                pass
            elif b["rc"] == 0 and row.get("forced"):
                ws.violate("R2-uninstall-while-running",
                           "remove SUCCEEDED while a launch held the version lease",
                           "docs/CONCURRENCY.md: uninstall while launching is "
                           "refused with BusyError, never a silent deletion under "
                           "a live process; FORMAT-0.1 §9.4")
            elif b["rc"] not in (0, 6) and not b["timed_out"]:
                ws.violate("R2-uninstall-code",
                           "remove during a live launch exited %d, not 6 (busy)"
                           % b["rc"],
                           "docs/ERRORS.md §1: BusyError is exit 6")
            if not row["launch_failed_closed"] and (
                    a["rc"] != 0 or "SLEPT_AT_LEAST_REQUESTED=yes" not in a["out"]):
                ws.violate("R3-run-disturbed",
                           "the running application did not complete its own work "
                           "(rc=%d)" % a["rc"],
                           "FORMAT-0.1 §9.4: a running application is not disturbed")
        elif oracle in ("running-undisturbed", "running-files-survive"):
            if not row["launch_failed_closed"] and (
                    a["rc"] != 0 or "SLEPT_AT_LEAST_REQUESTED=yes" not in a["out"]):
                ws.violate("R3-run-disturbed",
                           "the running application did not complete its own work "
                           "(rc=%d); the other participant exited %d"
                           % (a["rc"], b["rc"]),
                           "FORMAT-0.1 §9.4: installing, updating, rolling back or "
                           "repairing MUST NOT modify or remove the files of a "
                           "version that is currently executing")
        elif oracle == "observer-saw-one-whole-version":
            # B observes while A sits in the widened promote window. The claim
            # under test is docs/CONCURRENCY.md's: "activation (the `current`
            # flip) is atomic, so a launch never sees a torn mix."
            #
            # Two things would falsify it, and they are different failures:
            # an observer that SUCCEEDS while reporting nothing recognisable
            # (a half-built version), and an observer that FAILS silently (a
            # torn state with no diagnosis, which §9.2 forbids separately).
            if b["timed_out"]:
                ws.violate("R7-observer-hung",
                           "the observer did not return while the promote "
                           "window was held open",
                           "docs/CONCURRENCY.md: a reader takes no per-app "
                           "mutation lock, so it must never be blocked by one")
            elif b["rc"] == 0:
                text = (b["out"] or "") + (b["err"] or "")
                known = [m for m in self.marks.values() if (m + "=") in text]
                row["observer_saw"] = known
                if self.marks and not known and "run-observer" in row["schedule"]:
                    ws.violate("R7-observer-torn",
                               "a launch during the promote window exited 0 and "
                               "emitted no recognisable program output",
                               "docs/CONCURRENCY.md: the `current` flip is "
                               "atomic, so a launch never sees a torn mix")
            elif not (b["out"].strip() or b["err"].strip()):
                ws.violate("R7-observer-silent",
                           "the observer failed (rc=%d) during the promote "
                           "window and said nothing" % b["rc"],
                           "FORMAT-0.1 §9.2: it MUST report honestly that it is "
                           "damaged — it MUST NOT silently be missing files")

        # Every schedule, whatever else it asserts, must leave a coherent store.
        o = observe(ws.cli, APP_ID)
        row["final"] = o.as_dict()
        if o.installed and o.launchable is False:
            ws.violate("R4-incoherent-after-race",
                       "after %s the application is installed and will not launch "
                       "(%s)" % (row["schedule"], o.run_class),
                       "FORMAT-0.1 §9.2: at any instant at which a runtime could be "
                       "terminated, an application that reports as installed MUST "
                       "be launchable or MUST report honestly that it is damaged")
        if oracle == "absent-afterwards" and o.installed:
            ws.violate("R5-uninstall-lost",
                       "both participants finished and the application is still "
                       "installed (a=%d b=%d)" % (a["rc"], b["rc"]),
                       "FORMAT-0.1 §9.2: a failed or interrupted operation MUST "
                       "leave either the previous valid state or the new one")
        if oracle == "coherent-and-the-program-matches-the-record" and o.installed:
            # The record says one version; the program says which one it is. A
            # store that reports 2.0.0 and runs 1.0.0 is the ambiguous state §9.2
            # forbids, and only an oracle-bearing payload can see it.
            claimed = o.active
            if not self.marks:
                row["identity_gap"] = ("the two subject specimens share every "
                                       "oracle key, so which program ran cannot "
                                       "be recognised; this check did not run")
            elif claimed and o.run_stdout:
                want = "alt" if claimed == "2.0.0" else "plain"
                other = "plain" if want == "alt" else "alt"
                saw_want = (self.marks[want] + "=") in o.run_stdout
                saw_other = (self.marks[other] + "=") in o.run_stdout
                row["identity"] = {"claimed": claimed, "expected": want,
                                   "saw_expected": saw_want,
                                   "saw_other": saw_other}
                if saw_other and not saw_want:
                    ws.violate("R6-record-vs-program",
                               "`info` reports version %s, whose program emits %s, "
                               "and the program that ran emitted %s instead"
                               % (claimed, self.marks[want], self.marks[other]),
                               "FORMAT-0.1 §9.2: the active version of each "
                               "application and the content of that version MUST "
                               "be mutually consistent")

    def spec_id_for(self, version):
        if version == "2.0.0":
            return self.alt["id"] if self.alt else None
        return self.plain["id"] if self.plain else None


# --------------------------------------------------------------------------- #
#  TASK 3 — automatic failure minimisation                                    #
# --------------------------------------------------------------------------- #
#
# A 50,000-step failing trace is evidence and a terrible regression test. The
# minimised case becomes the permanent regression; the original is kept beside it
# under `provenance.original`, because a minimiser can be wrong — it can find a
# SMALLER failure that is not the one that was reported — and without the original
# nobody can tell.
#
# The signature is what "the same failure" means. It is the set of (kind, op,
# field, id) tuples, never the message text: reducing against prose would follow
# whichever wording happened to survive.

def failure_signature(trace):
    sig = set()
    for d in trace.get("divergences", []):
        sig.add((d.get("kind"), d.get("op"), d.get("field"), d.get("id")))
    for v in trace.get("violations", []):
        sig.add(("INVARIANT", None, None, v.get("id")))
    return frozenset(sig)


def ddmin(items, still_fails):
    """Zeller's delta debugging, on a list of operations.

    Returns the shortest subsequence this search finds that still produces the
    signature. `still_fails` is called O(n log n) times, so it must be the real
    thing — replaying against a model of a replay would minimise a fiction.
    """
    n = 2
    cur = list(items)
    while len(cur) >= 2:
        chunk = max(1, len(cur) // n)
        parts = [cur[i:i + chunk] for i in range(0, len(cur), chunk)]
        reduced = False
        for p in parts:                      # try each subset alone
            if len(p) < len(cur) and still_fails(p):
                cur, n, reduced = p, 2, True
                break
        if not reduced:
            for i, p in enumerate(parts):    # try each complement
                comp = [x for j, q in enumerate(parts) if j != i for x in q]
                if comp and len(comp) < len(cur) and still_fails(comp):
                    cur, n, reduced = comp, max(n - 1, 2), True
                    break
        if not reduced:
            if n >= len(cur):
                break
            n = min(len(cur), n * 2)
    return cur


class Minimiser:
    def __init__(self, cfg, runner):
        self.cfg = cfg
        self.runner = runner
        self.replays = 0

    def _replay(self, ops, spec_map):
        self.replays += 1
        return self.runner.run_explicit(ops, spec_map)

    def minimise_sequence(self, trace):
        target = failure_signature(trace)
        if not target:
            return {"error": "the trace records no failure to minimise"}
        ops = [o["op"] for o in trace["ops"]]
        spec_map = dict(trace.get("fixture") or {})

        def fails(cand):
            t = self._replay(cand, spec_map)
            return target.issubset(failure_signature(t))

        if not fails(ops):
            return {"error": "the original trace did not reproduce on replay",
                    "note": ("a failure that does not survive a replay is either "
                             "order-dependent in a way the trace does not capture "
                             "or genuinely intermittent; it is reported as such "
                             "rather than minimised into something else"),
                    "provenance": {"original": trace}}
        small = ddmin(ops, fails)

        # Simplify the fixture: drive every version from the SIMPLEST specimen the
        # corpus offers, and keep the simplification only if the failure survives.
        simple = self.cfg.corpus.pick("plain")
        if simple:
            flat = {v: simple["id"] for v in spec_map}
            t = self.runner.run_explicit(small, flat)
            self.replays += 1
            if target.issubset(failure_signature(t)):
                spec_map = flat

        final = self._replay(small, spec_map)
        return {
            "minimal": {"ops": small, "fixture": spec_map,
                        "signature": sorted(map(list, target))},
            "confirmed": target.issubset(failure_signature(final)),
            "replays": self.replays,
            "reduction": {"from_ops": len(ops), "to_ops": len(small)},
            "reproducer": {
                "how": ("python3 tests/workloads/explore.py replay --ops %s"
                        % ",".join(small)),
                "trace": final},
            "provenance": {
                "note": ("the original trace is retained verbatim: a minimiser can "
                         "land on a DIFFERENT, smaller failure, and only the "
                         "original shows whether it did"),
                "original": trace},
        }

    def minimise_case(self, case, seed):
        """Greedy per-dimension simplification of a sampled cross-product case."""
        simplest = {"specimen": "plain", "payload": "native-elf", "chain": "native",
                    "launch_mode": "console", "sandbox": "default",
                    "arguments": "none", "environment": "minimal",
                    "filesystem": "clean", "lifecycle": "fresh",
                    "concurrency": "none"}
        base = run_case(self.cfg, seed, case)
        target = frozenset((v["id"],) for v in base["violations"])
        if not target:
            return {"error": "the case records no violation to minimise"}
        cur = dict(case)
        for dim, simple in simplest.items():
            if cur.get(dim) == simple or dim not in cur:
                continue
            trial = dict(cur)
            trial[dim] = simple
            r = run_case(self.cfg, seed, trial)
            self.replays += 1
            if target.issubset(frozenset((v["id"],) for v in r["violations"])):
                cur = trial
        final = run_case(self.cfg, seed, cur)
        return {"minimal": {"case": cur, "case_id": case_id(seed, cur)},
                "confirmed": target.issubset(
                    frozenset((v["id"],) for v in final["violations"])),
                "replays": self.replays,
                "reproducer": {"how": "python3 tests/workloads/explore.py sample "
                                      "--seed %s --replay %s"
                                      % (seed, case_id(seed, cur))},
                "provenance": {"original": base}}


# --------------------------------------------------------------------------- #
#  cost — measure before sizing anything                                      #
# --------------------------------------------------------------------------- #

def measure_cost(cfg, samples):
    """Per-operation cost, cold and warm, with the host load beside every number.

    Timings collected while unrelated heavy work runs are not timings of the thing
    being timed. The load average is printed for exactly that reason: a reader can
    discard the numbers instead of explaining them. This is the routine that found
    the PATH effect the module docstring describes.
    """
    plain = cfg.corpus.pick("plain")
    pkgs = {v: cfg.factory.package(plain, v) for v in VERSIONS}
    out = {"load_before": host_load(), "pinned_path": PINNED_PATH,
           "samples": samples, "ops": {}, "path_effect": {}}
    ws = Workspace(cfg, "cost")
    try:
        seq = [("install", ["install", pkgs["1.0.0"], "--yes", "--trust"]),
               ("list", ["list", "--json"]),
               ("info", ["info", APP_ID, "--json"]),
               ("run", ["run", APP_ID]),
               ("verify", ["verify", pkgs["1.0.0"]]),
               ("repair", ["repair", APP_ID]),
               ("update-by-install", ["install", pkgs["2.0.0"], "--yes", "--trust"]),
               ("rollback", ["rollback", APP_ID]),
               ("runtime-list", ["runtime", "list"]),
               ("doctor", ["doctor"]),
               ("remove", ["remove", APP_ID, "--purge-data", "--yes"]),
               ("run-absent", ["run", APP_ID])]
        acc = {k: [] for k, _ in seq}
        for i in range(samples):
            for name, argv in seq:
                r = ws.cli(*argv, label=name)
                acc[name].append(r["ms"])
        out["ops"] = {k: percentiles(v) for k, v in acc.items()}
        # The PATH effect, measured rather than asserted.
        host_path = os.environ.get("PATH", "")
        if host_path and host_path != PINNED_PATH:
            wide, narrow = [], []
            for _ in range(max(3, samples)):
                wide.append(ws.cli("doctor", env_overrides={"PATH": host_path},
                                   label="doctor(host PATH)")["ms"])
                narrow.append(ws.cli("doctor", label="doctor(pinned PATH)")["ms"])
            out["path_effect"] = {
                "host_path_entries": len(host_path.split(":")),
                "host_path_mnt_c_entries":
                    sum(1 for p in host_path.split(":") if p.startswith("/mnt/")),
                "doctor_host_path_ms": percentiles(wide),
                "doctor_pinned_path_ms": percentiles(narrow)}
    finally:
        ws.close()
    out["load_after"] = host_load()
    return out


# --------------------------------------------------------------------------- #
#  Wiring                                                                      #
# --------------------------------------------------------------------------- #

class Cfg:
    pass


def build_cfg(a):
    cfg = Cfg()
    cfg.lexe = os.path.abspath(a.lexe)
    if not os.access(cfg.lexe, os.X_OK):
        die("runtime not executable at %s (build it first)" % cfg.lexe)
    cfg.scratch = os.path.abspath(a.scratch)
    os.makedirs(cfg.scratch, exist_ok=True)
    if not os.path.exists(a.index):
        die("no corpus index at %s — regenerate: python3 %s/generate.py"
            % (a.index, HERE))
    cfg.corpus = Corpus(a.index)
    if not cfg.corpus.specimens:
        die("the corpus index at %s holds no baseline-ok specimen" % a.index)
    cfg.corpus_pe = a.index_pe if (a.index_pe and os.path.exists(a.index_pe)) else None
    cfg.corpus_portable = (a.index_portable
                           if (a.index_portable and os.path.exists(a.index_portable))
                           else None)
    cfg.factory = Factory(cfg.lexe, os.path.join(cfg.scratch, "pkgs"), cfg.corpus)
    cfg.tattletale = build_tattletale(cfg)
    cfg.keep = bool(getattr(a, "keep", False))
    cfg.hold_ms = int(getattr(a, "hold_ms", 2500))
    cfg.applock_hold_ms = int(getattr(a, "applock_hold_ms", 1200))
    cfg.commit_hold_ms = int(getattr(a, "commit_hold_ms", 1200))
    cfg.jobs = int(getattr(a, "jobs", 8))
    return cfg


def execution_witness(payload, witness=None):
    """A count of work done, derived from a DIFFERENT accumulator than the one
    the engine hands to emit() as `executed`.

    The first version of this guessed, by looking for whichever of a list of
    well-known keys the payload happened to carry. That was wrong, and wrong in
    the way this whole mechanism exists to catch: a model report carries BOTH
    `operations` and `minimised`, `minimised` is empty on a clean run, the guess
    took the empty list, and a campaign of 81,212 operations with zero
    divergences was refused with "the engine reports 81212 executed and its own
    records contain no minimised traces". A check that fires on a correct run is
    not a stricter check, it is a broken one, and it went out over a shared lane.

    So the witness is now SUPPLIED by each command, which knows which of its
    accumulators is genuinely a second one, and the guessing is gone. Where a
    command has no independent second count — `replay` and `reduce` each have
    exactly one list and it is the same list `executed` is derived from — it
    passes None, and the report says so rather than inventing one.

    `meta.executed` is the engine reporting on itself, and
    `against_lexe_matrix.sh` fails a lane when it is zero — which is the right
    guard read from the wrong place. The count and the guard come from the same
    code, so an engine that miscounted (planned units instead of run ones, or a
    sum over the wrong list) would satisfy its own guard with nothing behind it.
    That is docs/ERRORS.md §7 exactly: self-reporting machinery cannot detect
    its own absence.

    The two counts need not be EQUAL — a model counts every operation while its
    expectation tallies skip fixture actions — so only the zero/non-zero
    disagreement is an error, which is the disagreement that matters.

    Returns (count, what_was_counted), or (None, None) when the command has no
    second count to offer, which is reported rather than assumed away.
    """
    if witness is not None:
        count, label = witness
        return (None, None) if count is None else (int(count), label)
    return None, None


def emit(a, payload, failures, executed, headline, witness=None):
    witness, witness_of = execution_witness(payload, witness)
    payload["meta"] = {
        "headline": headline, "executed": executed, "failures": failures,
        "executed_witness": witness, "executed_witness_source": witness_of,
        "load_before": payload.get("load_before") or host_load(),
        "load_after": host_last_load(), "pinned_path": PINNED_PATH,
        "op_timeout_s": OP_TIMEOUT_S,
        "lexe": getattr(a, "lexe", None),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if a.out:
        with open(a.out, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        print("  report: %s" % a.out)
    print("\n  %s" % headline)
    # A lane that executed nothing must never read as success — checked twice,
    # by two counts that are not produced by the same arithmetic.
    if executed == 0:
        print("  FAIL — nothing was executed, which is not a pass")
        return 3
    if witness == 0:
        print("  FAIL — the engine reports %d executed and its own records "
              "contain no %s; one of the two is wrong and neither may be "
              "trusted" % (executed, witness_of))
        return 3
    if witness is None:
        print("  NOTE  no per-unit records in this report, so the executed "
              "count (%d) has only one observation behind it" % executed)
    return 1 if failures else 0


def host_last_load():
    return host_load()


def cmd_cost(a):
    cfg = build_cfg(a)
    r = measure_cost(cfg, a.samples)
    print("  host load before %s, after %s" % (r["load_before"], r["load_after"]))
    print("  %-22s %8s %8s %8s %8s %8s" % ("operation", "n", "median", "p95",
                                           "p99", "max"))
    for k, v in r["ops"].items():
        print("  %-22s %8d %8.1f %8.1f %8.1f %8.1f"
              % (k, v["n"], v["median"], v["p95"], v["p99"], v["max"]))
    if r["path_effect"]:
        pe = r["path_effect"]
        print("\n  PATH effect on `doctor` (a MEASUREMENT artefact, not a runtime "
              "cost):")
        print("    host PATH   %d entries, %d under /mnt: median %.0fms"
              % (pe["host_path_entries"], pe["host_path_mnt_c_entries"],
                 pe["doctor_host_path_ms"]["median"]))
        print("    pinned PATH %d entries:                  median %.0fms"
              % (len(PINNED_PATH.split(":")), pe["doctor_pinned_path_ms"]["median"]))
    return emit(a, r, 0, sum(v["n"] for v in r["ops"].values()),
                "cost: %d operations timed" % sum(v["n"] for v in r["ops"].values()),
                # `executed` sums the samples; this counts the operations that
                # produced a row at all. A timing loop that ran zero operations
                # and a sample counter that summed nothing fail differently.
                witness=(len(r["ops"]), "operations with a timing row"))


# --------------------------------------------------------------------------- #
#  Subcommands                                                                 #
# --------------------------------------------------------------------------- #


# A worker that raises is a defect in THIS engine, and it must be reported as one
# rather than taking the run down. The first full race run died 336 schedules in
# because one thread lost a packaging race, and the whole campaign produced no
# report at all — a harness bug that erased the evidence it was collecting.
HARNESS_ERRORS = []


def settled(fut, label):
    try:
        return fut.result()
    except Exception as e:  # noqa: BLE001 - deliberately broad; see above
        import traceback
        HARNESS_ERRORS.append({"label": label, "error": repr(e),
                               "traceback": traceback.format_exc()[-1500:]})
        print("  HARNESS-ERROR %s: %r" % (label, e))
        return None


def cmd_sample(a):
    cfg = build_cfg(a)
    dims, gaps = resolve_dimensions(cfg, cfg.corpus)
    plan = pairwise_plan(dims, a.seed, a.order)
    missing = coverage_gaps(dims, plan, a.order)
    if missing:
        # The sampler's own promise, checked. A generator that claims all-pairs
        # and silently misses some is the tooling reporting on itself, which is
        # the defect class this session already paid for once.
        print("  FAIL: the plan does not cover %d required %d-tuples"
              % (len(missing), a.order))
    if a.cases and a.cases > len(plan):
        rng = random.Random("extra|%s" % a.seed)
        while len(plan) < a.cases:
            plan.append({k: rng.choice(v) for k, v in dims.items()})
    if a.replay:
        plan = [c for c in plan if case_id(a.seed, c) == a.replay]
        if not plan:
            die("no case with id %s in the plan for seed %s" % (a.replay, a.seed))

    print("  dimensions: %s" % ", ".join("%s=%d" % (k, len(v))
                                         for k, v in dims.items()))
    print("  plan: %d cases for %d-way coverage (seed %s)"
          % (len(plan), a.order, a.seed))
    for g in gaps + cfg.corpus.gaps:
        print("  GAP  %s" % g)

    results, done = [], 0
    with futures.ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
        futs = {ex.submit(run_case, cfg, a.seed, c): c for c in plan}
        for f in futures.as_completed(futs):
            r = settled(f, "sample case")
            if r is None:
                done += 1
                continue
            results.append(r)
            done += 1
            if r["violations"]:
                for v in r["violations"]:
                    print("  FAIL [%s] %s: %s" % (r["case_id"], v["id"], v["detail"]))
            if done % 25 == 0:
                print("  ... %d/%d" % (done, len(plan)))

    executed = sum(1 for r in results if not r.get("skipped"))
    skipped = [r for r in results if r.get("skipped")]
    # A GAP is a check that could not run here. It is reported loudly and counted
    # separately: it is neither a pass nor a failure, and collapsing it into
    # either is how a capability becomes a claim.
    gaps_hit = [(r["case_id"], v) for r in results for v in r["violations"]
                if v.get("gap")]
    viol = [(r["case_id"], v) for r in results for v in r["violations"]
            if not v.get("gap")]
    for cid, v in gaps_hit[:5]:
        print("  GAP  [%s] %s: %s" % (cid, v["id"], v["detail"]))
    by_id = {}
    for cid, v in viol:
        by_id.setdefault(v["id"], []).append(cid)
    print("\n  executed %d cases, skipped %d, %d violations across %d distinct kinds"
          % (executed, len(skipped), len(viol), len(by_id)))
    for k, cids in sorted(by_id.items()):
        print("    %-28s %3d cases, first: %s" % (k, len(cids), cids[0]))
    payload = {"seed": a.seed, "order": a.order, "dimensions": dims,
               "coverage_gaps": [list(map(list, m)) for m in missing],
               "availability_gaps": gaps + cfg.corpus.gaps,
               "cases": results,
               "timing_ms": percentiles([r["ms"] for r in results
                                         if not r.get("skipped")])}
    payload["harness_errors"] = HARNESS_ERRORS
    return emit(a, payload, len(viol) + len(missing) + len(HARNESS_ERRORS), executed,
                "sample: %d cases, %d violations" % (executed, len(viol)),
                witness=(len(results), "case records"))


def cmd_model(a):
    cfg = build_cfg(a)
    global INJECT
    INJECT = parse_inject(getattr(a, "inject", None))
    if INJECT:
        print("  INJECTED MODEL FAULT %s — this run tests the MINIMISER, "
              "not .LEXE" % a.inject)
    runner = SequenceRunner(cfg)
    if not all(runner.pkgs.values()):
        die("could not pack the model's subject packages")

    traces, done = [], 0
    lengths = random.Random("len|%s" % a.seed)
    plan = [(i, lengths.randint(a.min_len, a.max_len)) for i in range(a.sequences)]
    t0 = time.time()
    with futures.ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
        futs = [ex.submit(runner.run_sequence, a.seed, i, n, a.illegal_bias)
                for i, n in plan]
        for f in futures.as_completed(futs):
            t = settled(f, "model sequence")
            if t is None:
                done += 1
                continue
            traces.append(t)
            done += 1
            if done % max(1, a.sequences // 10) == 0:
                print("  ... %d/%d sequences (%.0f/s)"
                      % (done, a.sequences, done / max(1e-9, time.time() - t0)))
    elapsed = time.time() - t0

    # --- divergences, grouped by the thing that is wrong rather than by trace
    groups = {}
    for t in traces:
        for d in t["divergences"]:
            k = (d.get("kind"), d.get("op"), d.get("state"), d.get("field"),
                 d.get("id"), str(d.get("expected")), str(d.get("got")))
            g = groups.setdefault(k, {"kind": d.get("kind"), "op": d.get("op"),
                                      "state": d.get("state"),
                                      "field": d.get("field"),
                                      "id": d.get("id"),
                                      "expected": d.get("expected"),
                                      "got": d.get("got"),
                                      "citation": d.get("citation"),
                                      "message": d.get("message"),
                                      "count": 0, "example": t["index"]})
            g["count"] += 1

    # --- the consistency oracle: same abstract state + same op => same answer.
    # This needs no specification at all, which is exactly why it is here.
    cons = {}
    for t in traces:
        for u in t["underspec"]:
            cons.setdefault((tuple(u["key"]), u["op"]), {})\
                .setdefault(u["class"], 0)
            cons[(tuple(u["key"]), u["op"])][u["class"]] += 1
    inconsistent = {k: v for k, v in cons.items() if len(v) > 1}

    # --- coverage, because "0 divergences" over a walk that never left the
    # first state is not a result. The asserted-operations ratio below says how
    # much of the work was CHECKED; this says how much of the machine was
    # REACHED, and the two answer different objections. A campaign that reports
    # neither is asking to be believed.
    cells, states_seen, ops_seen = set(), set(), set()
    for t in traces:
        for e in t["ops"]:
            if e.get("fixture"):
                ops_seen.add(e["op"])
                continue
            cells.add((e.get("model_state"), e.get("op")))
            states_seen.add(e.get("model_state"))
            ops_seen.add(e.get("op"))
    final_states = {}
    for t in traces:
        fs = t.get("final_model")
        final_states[fs] = final_states.get(fs, 0) + 1
    coverage = {"distinct_state_op_cells": len(cells),
                "distinct_model_states_entered": len(states_seen),
                "distinct_operations_attempted": len(ops_seen),
                "model_states": sorted(x for x in states_seen if x),
                "operations": sorted(x for x in ops_seen if x),
                "final_state_distribution": final_states}

    ops_run = sum(len(t["ops"]) for t in traces)
    kinds = {}
    for t in traces:
        for k, v in (t.get("kinds") or {}).items():
            kinds[k] = kinds.get(k, 0) + v
    asserted = kinds.get(PIN, 0) + kinds.get(ANY_REFUSE, 0)
    print("\n  %d sequences, %d operations, %.1fs wall, %.0f sequences/s"
          % (len(traces), ops_run, elapsed, len(traces) / max(1e-9, elapsed)))
    print("  %d divergence groups, %d inconsistent (state,op) cells"
          % (len(groups), len(inconsistent)))
    print("  coverage: %d distinct (abstract state, operation) cells across %d "
          "model states and %d operations; final states %s"
          % (coverage["distinct_state_op_cells"],
             coverage["distinct_model_states_entered"],
             coverage["distinct_operations_attempted"],
             dict(sorted(final_states.items(), key=lambda kv: -kv[1])[:6])))
    # A clean run is evidence only in proportion to how much of it was ASSERTED.
    # Printed so that "0 divergences" can never be read as "0 divergences out of
    # nothing checked".
    print("  of those operations, %d carried a PINNED expectation with a cited "
          "sentence, %d required a refusal without a pinned code, and %d were "
          "UNDERSPEC and judged only by the consistency oracle"
          % (kinds.get(PIN, 0), kinds.get(ANY_REFUSE, 0), kinds.get(UNDERSPEC, 0)))
    for g in sorted(groups.values(), key=lambda g: -g["count"]):
        print("    %-14s %-18s state=%-14s expected=%s got=%s  x%d"
              % (g["kind"], g["op"] or g["field"] or g["id"], g["state"],
                 g["expected"], g["got"], g["count"]))
        if g["citation"]:
            print("        %s" % g["citation"])
    for (key, op), classes in sorted(inconsistent.items(), key=lambda kv: str(kv[0])):
        print("    INCONSISTENT  %-18s in %s -> %s" % (op, key[0], dict(classes)))

    # --- the pinned scenarios and the two named gaps
    perms = run_permission_scenarios(cfg)
    perm_fail = [p for p in perms if p["ok"] is False]
    for p in perms:
        mark = "PASS" if p["ok"] else ("SKIP" if p["ok"] is None else "FAIL")
        print("  %s  §9.5 scenario: %s" % (mark, p["id"]))
        if p["ok"] is False:
            bad = [s for s in p["steps"] if s.get("ok") is False]
            for s in bad:
                print("        step %s wanted %s, got %d — %s"
                      % (s["op"], s["want"], s["rc"], s.get("message", "")))
            print("        %s" % p["why"])
    tax = check_taxonomy(cfg)
    for t in tax:
        if t.get("skipped"):
            print("  SKIP  taxonomy observation %s: %s" % (t["id"], t["skipped"]))
            continue
        print("  NOTE  taxonomy: %s" % t["id"])
        if "already_current_rc" in t:
            print("        already-current install exits %s; a package that is "
                  "genuinely broken exits %s"
                  % (t["already_current_rc"], t["genuinely_broken_package_rc"]))
        else:
            print("        no rollback target exits %s; no such application exits "
                  "%s; indistinguishable=%s"
                  % (t["no_rollback_target_rc"], t["no_such_application_rc"],
                     t["indistinguishable"]))
    stop = check_stop_verb(cfg)
    print("  NOTE  `lexe stop` -> %s (%s)" % (stop["class"], stop["message"][:80]))
    doc = check_doctor_convergence(cfg)
    print("  NOTE  doctor: reports problems with exit 0 = %s, converges = %s"
          % (doc["reports_problems_with_exit_zero"], doc["converged"]))

    # --- minimise, if anything failed and it was asked for
    minimised = []
    if a.minimise and groups:
        seen = set()
        for t in sorted(traces, key=lambda t: len(t["ops"])):
            sig = failure_signature(t)
            if not sig or sig in seen:
                continue
            seen.add(sig)
            m = Minimiser(cfg, runner).minimise_sequence(t)
            minimised.append(m)
            if len(minimised) >= a.minimise:
                break
        for m in minimised:
            if "minimal" in m:
                print("  MINIMISED %d ops -> %d: %s"
                      % (m["reduction"]["from_ops"], m["reduction"]["to_ops"],
                         " ".join(m["minimal"]["ops"])))
            else:
                print("  MINIMISE  %s" % m.get("error"))

    # The minimiser's own self-test. A reducer that is never checked against a
    # known answer is a reducer nobody has tested.
    selftest = None
    if a.expect_minimal:
        want = [o for o in a.expect_minimal.split(",") if o]
        got = [m["minimal"]["ops"] for m in minimised if "minimal" in m]
        ok = any(g == want for g in got)
        selftest = {"want": want, "got": got, "ok": ok}
        print("  %s  minimiser self-test: expected %s, reducers produced %s"
              % ("PASS" if ok else "FAIL", want, got))

    failures = len(groups) + len(inconsistent) + len(perm_fail) + len(HARNESS_ERRORS)
    if INJECT:
        # An injected run says nothing about the runtime, so its divergences must
        # not be counted as findings. Only the self-test verdict counts.
        failures = (0 if (selftest or {}).get("ok") else 1) + len(HARNESS_ERRORS)
    payload = {"seed": a.seed, "sequences": len(traces), "operations": ops_run,
               "elapsed_s": round(elapsed, 2),
               "sequences_per_s": round(len(traces) / max(1e-9, elapsed), 1),
               "expectation_kinds": kinds, "asserted_operations": asserted,
               "coverage": coverage,
               "divergence_groups": list(groups.values()),
               "inconsistent_cells": [{"state_key": list(k[0]), "op": k[1],
                                       "classes": v}
                                      for k, v in inconsistent.items()],
               "permission_scenarios": perms, "stop_verb": stop,
               "taxonomy_observations": tax,
               "doctor": doc, "minimised": minimised,
               "harness_errors": HARNESS_ERRORS,
               "injected_fault": getattr(a, "inject", None),
               "minimiser_selftest": selftest,
               "traces": traces if a.keep_traces else
                         [t for t in traces if t["divergences"]]}
    return emit(a, payload, failures, ops_run,
                "model: %d sequences / %d operations, %d divergence groups, "
                "%d inconsistent cells" % (len(traces), ops_run, len(groups),
                                           len(inconsistent)),
                # `ops_run` sums the per-trace operation lists. This sums the
                # expectation tallies, which are incremented at a different
                # place in the loop, so a walk that appended operations without
                # ever evaluating one — or evaluated without appending — shows
                # up as one of the two being zero.
                witness=(sum(kinds.values()), "evaluated expectations"))


def cmd_race(a):
    cfg = build_cfg(a)
    runner = RaceRunner(cfg)
    if runner.long is None:
        print("  GAP  no long-running specimen: the FORCED schedules degrade to "
              "the barrier, which is luck rather than forcing")
    jobs = []
    for sched in SCHEDULES:
        if a.only and a.only not in sched[0]:
            continue
        for rep in range(a.repeats):
            for pressure in ((False, True) if a.pressure else (False,)):
                jobs.append((sched, rep, pressure))
    if not jobs:
        die("no schedule selected")
    print("  %d schedules x %d repeats%s = %d runs "
          "(trigger payload %dms, applock hold %dms, commit hold %dms)"
          % (len({j[0][0] for j in jobs}), a.repeats,
             " x {no pressure, cpu pressure}" if a.pressure else "", len(jobs),
             cfg.hold_ms, cfg.applock_hold_ms, cfg.commit_hold_ms))

    rows, done = [], 0
    t0 = time.time()
    with futures.ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
        futs = [ex.submit(runner.run, s, r, p) for (s, r, p) in jobs]
        for f in futures.as_completed(futs):
            row = settled(f, "race schedule")
            if row is None:
                done += 1
                continue
            rows.append(row)
            done += 1
            for v in row["violations"]:
                print("  FAIL [%s rep %d%s] %s: %s"
                      % (row["schedule"], row["rep"],
                         " +pressure" if row["pressure"] else "", v["id"],
                         v["detail"]))
            if done % max(1, len(jobs) // 8) == 0:
                print("  ... %d/%d" % (done, len(jobs)))
    elapsed = time.time() - t0

    executed = sum(1 for r in rows if not r.get("skipped"))
    viol = [(r, v) for r in rows for v in r["violations"]]
    forced = sum(1 for r in rows if r.get("forced"))
    per = {}
    for r in rows:
        d = per.setdefault(r["schedule"], {"runs": 0, "violations": 0,
                                           "forced": 0, "outcomes": {}})
        d["runs"] += 1
        d["violations"] += len(r["violations"])
        d["forced"] += 1 if r.get("forced") else 0
        if r.get("a") and r.get("b"):
            d["outcomes"][r["a"]["class"] + " | " + r["b"]["class"]] = \
                d["outcomes"].get(r["a"]["class"] + " | " + r["b"]["class"], 0) + 1
    # The forced ratio, split by how the window was entered. A single ratio
    # hides the fact that "trigger" and "hold" schedules are forced by different
    # mechanisms and a barrier schedule cannot be forced at all, so a campaign
    # that swapped one for another would show no change in the headline number.
    by_mode = {}
    for r in rows:
        m = dict((s[0], s[1]) for s in SCHEDULES).get(r["schedule"], "?")
        d = by_mode.setdefault(m, {"runs": 0, "forced": 0})
        d["runs"] += 1
        d["forced"] += 1 if r.get("forced") else 0
    lost = {}
    for r in rows:
        if r.get("force_witness") and not r.get("forced"):
            lost[r["force_witness"]] = lost.get(r["force_witness"], 0) + 1
    print("\n  %d runs in %.1fs, %d entered a FORCED window, %d violations"
          % (executed, elapsed, forced, len(viol)))
    for m, d in sorted(by_mode.items()):
        print("    mode %-12s %3d runs, %3d forced (%s)"
              % (m, d["runs"], d["forced"],
                 "%.0f%%" % (100.0 * d["forced"] / d["runs"]) if d["runs"]
                 else "n/a"))
    for why, n in sorted(lost.items(), key=lambda kv: -kv[1]):
        print("    window lost x%-4d %s" % (n, why))
    failed_closed = sum(1 for r in rows if r.get("launch_failed_closed"))
    print("  %d launches failed CLOSED on the documented resolve->lease TOCTOU "
          "(not a violation; a high count means a weak trigger)" % failed_closed)
    for sid, d in sorted(per.items()):
        print("    %-30s runs=%3d forced=%3d viol=%d  %s"
              % (sid, d["runs"], d["forced"], d["violations"],
                 ", ".join("%s x%d" % (k, v)
                           for k, v in sorted(d["outcomes"].items()))))
    payload = {"runs": rows, "per_schedule": per, "elapsed_s": round(elapsed, 2),
               "forced_runs": forced, "forced_by_mode": by_mode,
               "windows_lost": lost, "harness_errors": HARNESS_ERRORS,
               "applock_hold_ms": cfg.applock_hold_ms,
               "commit_hold_ms": cfg.commit_hold_ms,
               "still_unforceable": STILL_UNFORCEABLE}
    return emit(a, payload, len(viol) + len(HARNESS_ERRORS), executed,
                "race: %d runs, %d forced, %d violations"
                % (executed, forced, len(viol)),
                witness=(len(rows), "schedule rows"))


# This used to be a REQUEST. The hold points it asked for now exist
# (LEXE_TEST_HOLD_APPLOCK_MS in the lock layer, LEXE_TEST_HOLD_BEFORE_COMMIT_MS
# at the promote), so the schedules that needed them — install||install,
# repair||repair, update||rollback, update||repair — are forced rather than
# hoped for, and the barrier-under-pressure fallback is gone from those rows.
#
# What remains genuinely unforceable is recorded here instead, because a lane
# that stops listing its blind spots stops having any.
STILL_UNFORCEABLE = (
    "Two windows are still entered by luck rather than forced. (1) Schedules "
    "whose participant A takes no per-application mutation lock: "
    "`doctor --repair` operates on integration state, not on one app, so there "
    "is no per-app critical section to hold it in, and `service-start||update` "
    "starts with a launch. Those two remain barrier schedules and are reported "
    "as NOT forced. (2) The interval between `flock` returning and the owner "
    "record being written: the witness used here requires BOTH, so a run that "
    "lands between them is reported as a lost window with the reason, not "
    "silently counted. Neither is worth another production hook — the first "
    "would need a lock that does not exist, and the second is smaller than the "
    "scheduling granularity the harness can act on.")


def cmd_reduce(a):
    cfg = build_cfg(a)
    global INJECT
    runner = SequenceRunner(cfg)
    with open(a.trace) as f:
        doc = json.load(f)
    # A report carries the conditions it was produced under, and `reduce` restores
    # them. Without this, minimising a report from an injected-fault run replayed
    # against a model with no fault, found no divergence, and reported "the
    # original trace did not reproduce" — which is the honest answer to the wrong
    # question. A reducer that silently changes the conditions is reducing a
    # different bug.
    if isinstance(doc, dict) and doc.get("injected_fault"):
        INJECT = parse_inject(doc["injected_fault"])
        print("  restoring the report's injected model fault: %s"
              % doc["injected_fault"])
    traces = doc.get("traces") if isinstance(doc, dict) else doc
    if isinstance(doc, dict) and "ops" in doc:
        traces = [doc]
    traces = [t for t in (traces or []) if t.get("divergences")]
    if not traces:
        die("no failing trace in %s" % a.trace)
    out = []
    for t in sorted(traces, key=lambda t: len(t["ops"]))[:a.limit]:
        m = Minimiser(cfg, runner).minimise_sequence(t)
        out.append(m)
        if "minimal" in m:
            print("  %d ops -> %d ops : %s  (confirmed=%s, %d replays)"
                  % (m["reduction"]["from_ops"], m["reduction"]["to_ops"],
                     " ".join(m["minimal"]["ops"]), m["confirmed"], m["replays"]))
        else:
            print("  %s" % m.get("error"))
    return emit(a, {"minimised": out}, 0, len(out),
                "reduce: %d traces minimised" % len(out))


def cmd_replay(a):
    cfg = build_cfg(a)
    runner = SequenceRunner(cfg)
    ops = [o.strip() for o in a.ops.split(",") if o.strip()]
    t = runner.run_explicit(ops, None)
    for o in t["ops"]:
        print("  %-18s rc=%-3s %s" % (o.get("op"), o.get("rc", "-"),
                                      o.get("class", "")))
    for d in t["divergences"]:
        print("  DIVERGENCE %s" % json.dumps(d, default=str))
    return emit(a, t, len(t["divergences"]), len(t["ops"]),
                "replay: %d ops, %d divergences" % (len(t["ops"]),
                                                    len(t["divergences"])))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--lexe", default=os.path.join(REPO, "build-linux", "lexe"))
    ap.add_argument("--index", default="/tmp/lexe-workloads/index.json")
    ap.add_argument("--index-pe", default=None)
    ap.add_argument("--index-portable", default=None)
    ap.add_argument("--scratch", default=os.path.join(
        tempfile.gettempdir(), "lexe-explore"))
    ap.add_argument("--out", default=None, help="write the JSON report here")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--keep", action="store_true",
                    help="keep every scratch LEXE_HOME (for debugging)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("cost", help="measure per-operation cost first")
    c.add_argument("--samples", type=int, default=5)
    c.set_defaults(fn=cmd_cost)

    s = sub.add_parser("sample", help="deterministic pairwise cross-product")
    s.add_argument("--seed", default="1")
    s.add_argument("--order", type=int, default=2, choices=(2, 3))
    s.add_argument("--cases", type=int, default=0,
                   help="pad the plan to at least N cases (seeded)")
    s.add_argument("--replay", default=None, help="execute only this case id")
    s.set_defaults(fn=cmd_sample)

    m = sub.add_parser("model", help="model-based lifecycle testing at scale")
    m.add_argument("--seed", default="1")
    m.add_argument("--sequences", type=int, default=2000)
    m.add_argument("--min-len", type=int, default=2)
    m.add_argument("--max-len", type=int, default=12)
    m.add_argument("--illegal-bias", type=float, default=0.45,
                   help="probability of preferring an op the model says must be "
                        "refused; the interesting cases are the illegal ones")
    m.add_argument("--minimise", type=int, default=0,
                   help="minimise up to N distinct failing signatures")
    m.add_argument("--keep-traces", action="store_true")
    m.add_argument("--inject", default=None,
                   help="inject a MODEL fault to exercise the minimiser, "
                        "e.g. rollback:ABSENT:0 — never a claim about .LEXE")
    m.add_argument("--expect-minimal", default=None,
                   help="with --inject: the op sequence the reducer must reach, "
                        "comma separated. The self-test for TASK 3.")
    m.set_defaults(fn=cmd_model)

    r = sub.add_parser("race", help="generated concurrent schedules")
    r.add_argument("--repeats", type=int, default=10)
    r.add_argument("--only", default=None)
    r.add_argument("--pressure", action="store_true",
                   help="also run every schedule under CPU pressure")
    r.add_argument("--applock-hold-ms", type=int, default=1200,
                   help="LEXE_TEST_HOLD_APPLOCK_MS given to participant A in "
                        "'hold' schedules, so B is forced into its critical "
                        "section rather than arriving there by luck")
    r.add_argument("--commit-hold-ms", type=int, default=1200,
                   help="LEXE_TEST_HOLD_BEFORE_COMMIT_MS given to participant A "
                        "in 'hold-commit' schedules, which widens the promote")
    r.add_argument("--hold-ms", type=int, default=2500,
                   help="how long the FORCED schedules hold a launch lease")
    r.set_defaults(fn=cmd_race)

    d = sub.add_parser("reduce", help="minimise failing traces from a report")
    d.add_argument("--trace", required=True)
    d.add_argument("--limit", type=int, default=5)
    d.set_defaults(fn=cmd_reduce)

    p = sub.add_parser("replay", help="execute one explicit operation sequence")
    p.add_argument("--ops", required=True, help="comma-separated op names")
    p.set_defaults(fn=cmd_replay)

    a = ap.parse_args()
    print("== explore: %s ==" % a.cmd)
    print("  runtime %s" % a.lexe)
    print("  corpus  %s" % a.index)
    print("  load    %s   (numbers collected under load are labelled, not "
          "explained away)" % " ".join(host_load()))
    rc = a.fn(a)
    sys.exit(rc)


if __name__ == "__main__":
    main()

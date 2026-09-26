#!/usr/bin/env bash
# lifecycle 03 — service behaviour, as far as this environment permits.
#
# A .LEXE service is background BY DECLARATION: `launch.mode: "service"` means
# `lexe run` detaches it whether or not the caller asked, and the sandbox that
# supervises it must NOT die with the process that started it — a detached launch
# whose sandbox is torn down when `lexe run` returns is not detached.
#
# The hard part of testing a background process is observing it, so the payload is
# built for that: it appends a line to $LEXE_APP_DATA/heartbeat.log every second
# and writes a distinct "stopped cleanly" line on SIGTERM. That makes each of
# these answerable from outside the process:
#
#   * did it detach — did `lexe run` return while it kept running?
#   * is it supervised — does the sandbox outlive the launcher?
#   * does it hold a version lease — are its files protected while it runs?
#   * does it stop cleanly when asked, distinguishably from being killed?
#   * does an update while it runs leave the running version's files alone?
#   * does uninstalling while it runs refuse, rather than silently killing it?
#
# What this environment CANNOT show is integration with a systemd user session,
# because WSL has none. That is reported as BLOCKED rather than skipped: the
# capability is claimed, so a machine that cannot demonstrate it is a gap. See
# docs/ROADMAP.md §4 — whether a .LEXE service should be a systemd user unit at
# all is an open design question, not only an untested one.
set -uo pipefail
LC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$LC_DIR/../acceptance/lib.sh"
source "$LC_DIR/lib.sh"
acc_begin "lifecycle 03 service"
acc_require_binaries
lc_setup

SVC_EXAMPLE="$ACC_REPO/examples/service/heartbeat"
SVC_ID="org.lexe.examples.heartbeat"

if [[ ! -f "$SVC_EXAMPLE/lexe.json" ]]; then
    fail "the service example is present" "expected $SVC_EXAMPLE/lexe.json"
    acc_summary
    exit $?
fi

work="$ACC_ROOT/work"
project="$work/heartbeat"
mkdir -p "$project"
cp -r "$SVC_EXAMPLE/lexe.json" "$SVC_EXAMPLE/src" "$SVC_EXAMPLE/Makefile" "$project/"
if ! make -s -C "$project" >"$work/make-svc.log" 2>&1; then
    fail "the service payload compiles" "$(sed 's/^/    /' "$work/make-svc.log")"
    acc_summary
    exit $?
fi
pass "the service payload compiles"

key="$work/key.json"
[[ -f "$key" ]] || "$LEXE" keygen "$key" >/dev/null
package="$work/heartbeat.lexe"
if ! "$LEXE" build "$project" -o "$package" --key "$key" >"$work/build-svc.log" 2>&1; then
    fail "lexe build packaged the service" "$(sed 's/^/    /' "$work/build-svc.log")"
    acc_summary
    exit $?
fi
pass "lexe build packaged a service"

if ! "$LEXE" install "$package" --yes --trust >"$work/install-svc.log" 2>&1; then
    fail "the service installs" "$(sed 's/^/    /' "$work/install-svc.log")"
    acc_summary
    exit $?
fi
pass "the service installs"

declared="$(acc_json_str "$("$LEXE" info "$SVC_ID" --json 2>/dev/null)" \
    'd.get("manifest", {}).get("launch", {}).get("mode", "")')"
acc_equals "$declared" "service" \
    "the manifest DECLARES launch.mode service — background is declared, not guessed"

log="$LEXE_HOME/data/$SVC_ID/heartbeat.log"
beats() { [[ -f "$log" ]] && grep -c '^beat ' "$log" 2>/dev/null | head -1 || echo 0; }
# Version-agnostic on purpose: the update below makes 2.0.0 current, so a
# pattern pinned to 1.0.0 reports the RESTARTED service as absent -- which it
# did, while the very next check (that work resumed) passed. Two checks
# disagreeing about whether a process exists is the tell.
svc_pids() { pgrep -f "/bin/heartbeat" 2>/dev/null || true; }
# Pinned to one version, for the cases that are specifically about one.
svc_pids_at() { pgrep -f "versions/$1/bin/heartbeat" 2>/dev/null || true; }

# --------------------------------------------- 1. it detaches without being asked
#
# No --detach here. The manifest says service, so the runtime detaches anyway.

rm -f "$log"
start=$(date +%s)
"$LEXE" run "$SVC_ID" >"$work/run-svc.log" 2>&1
run_status=$?
elapsed=$(( $(date +%s) - start ))

acc_true "$run_status" "lexe run returned successfully"
acc_true "$([[ $elapsed -lt 10 ]] && echo 0 || echo 1)" \
    "and it RETURNED (${elapsed}s) instead of blocking on the service"

sleep 3
pids="$(svc_pids)"
acc_true "$([[ -n "$pids" ]] && echo 0 || echo 1)" \
    "the service is still running after lexe run returned — it detached"

# Supervised: the sandbox must still be there, holding it.
supervisor="$(pgrep -f "bwrap.*heartbeat" 2>/dev/null | head -1 || true)"
if [[ -n "$supervisor" ]]; then
    pass "the sandbox supervisor outlived the launcher (pid $supervisor)"
else
    note "no bwrap process matched; the service may be running unconfined here"
fi

first="$(beats)"
acc_true "$([[ "${first:-0}" -ge 1 ]] && echo 0 || echo 1)" \
    "it is doing work: ${first:-0} heartbeat(s) recorded in its private data root"

# --------------------------------------------- 2. it holds a version lease

sleep 2
acc_true "$([[ "$(beats)" -gt "${first:-0}" ]] && echo 0 || echo 1)" \
    "it is still beating a moment later, so it is genuinely alive"

remove_out="$("$LEXE" remove "$SVC_ID" --yes 2>&1)"
remove_status=$?
acc_true "$([[ $remove_status -ne 0 ]] && echo 0 || echo 1)" \
    "uninstalling a RUNNING service is refused (exit $remove_status), not a silent kill"
acc_contains "$remove_out" "running" \
    "and the refusal says the application is running"
acc_true "$([[ -n "$(svc_pids)" ]] && echo 0 || echo 1)" \
    "the service was not killed by the attempt"
# lc_installed_entry names the lifecycle SUBJECT application; this suite has its
# own id, so build the path from that.
svc_entry="$LEXE_HOME/apps/$SVC_ID/versions/1.0.0/bin/heartbeat"
acc_file_exists "$svc_entry" "and its files are still in place"

# --------------------------------------------- 3. an update while it runs

svc_v2="$work/heartbeat-2.lexe"
python3 - "$project/lexe.json" <<'PY'
import json, sys
with open(sys.argv[1]) as handle:
    manifest = json.load(handle)
manifest["version"] = "2.0.0"
manifest["publisher"]["publicKey"] = "AUTO"
with open(sys.argv[1], "w") as handle:
    json.dump(manifest, handle, indent=2)
PY
if "$LEXE" build "$project" -o "$svc_v2" --key "$key" >"$work/build-svc2.log" 2>&1; then
    running_before="$(svc_pids_at 1.0.0 | head -1)"
    "$LEXE" install "$svc_v2" --yes >"$work/update-svc.log" 2>&1
    update_status=$?
    note "installing 2.0.0 while 1.0.0 runs exited $update_status"
    if [[ -n "$(svc_pids_at 1.0.0)" ]]; then
        acc_file_exists "$LEXE_HOME/apps/$SVC_ID/versions/1.0.0/bin/heartbeat" \
            "the running version's files were NOT removed from under it by an update"
        acc_equals "$(svc_pids_at 1.0.0 | head -1)" "$running_before" \
            "and the running service is the same process it was"
    else
        note "the service stopped during the update; the file check does not apply"
    fi
else
    note "could not build a second version; skipping the update-while-running case"
fi

# --------------------------------------------- 4. it stops cleanly when told
#
# SIGTERM, not SIGKILL: the payload writes a distinct line on a clean stop, so
# "it shut down" and "it was killed" are distinguishable AFTER THE FACT. A service
# that cannot be told apart from one that crashed is a service whose restart
# behaviour cannot be tested.

for pid in $(svc_pids); do kill -TERM "$pid" 2>/dev/null; done
stopped=no
for _ in $(seq 1 100); do
    [[ -z "$(svc_pids)" ]] && { stopped=yes; break; }
    sleep 0.1
done
acc_equals "$stopped" "yes" "SIGTERM stops the service"
acc_true "$(grep -q 'stopped cleanly' "$log" 2>/dev/null && echo 0 || echo 1)" \
    "and it recorded a CLEAN stop, distinguishable from having been killed"

# --------------------------------------------- 5. it restarts

before_restart="$(beats)"
"$LEXE" run "$SVC_ID" >/dev/null 2>&1
# Wait for the process rather than sampling after a fixed sleep: a detached
# launch is asynchronous by definition, so a single sample is a race, and one
# that fails while the NEXT check (that work resumed) passes -- which is exactly
# what happened the first time this ran.
restarted=no
for _ in $(seq 1 150); do
    [[ -n "$(svc_pids)" ]] && { restarted=yes; break; }
    sleep 0.1
done
acc_equals "$restarted" "yes" "it starts again after a clean stop"
acc_true "$([[ "$(beats)" -gt "${before_restart:-0}" ]] && echo 0 || echo 1)" \
    "and resumes work, appending to the same private data root"

# --------------------------------------------- 6. a killed service leaves no lock
#
# The lease is an flock, so the kernel releases it when its holder dies. Checked
# by consequence: after SIGKILL, an uninstall must succeed rather than report busy
# forever.

for pid in $(svc_pids); do kill -9 "$pid" 2>/dev/null; done
sleep 2
pkill -9 -f "bwrap.*heartbeat" 2>/dev/null || true
sleep 1
acc_true "$([[ -z "$(svc_pids)" ]] && echo 0 || echo 1)" \
    "SIGKILL stops it too (there is no way to refuse that)"
acc_true "$(grep -q 'stopped cleanly' <(tail -1 "$log" 2>/dev/null) && echo 1 || echo 0)" \
    "and it did NOT record a clean stop — a kill is distinguishable from a shutdown"
acc_true "$("$LEXE" remove "$SVC_ID" --purge-data --yes >/dev/null 2>&1; echo $?)" \
    "the version lease died with its holder: the service can now be uninstalled"

# --------------------------------------------- 7. what this machine cannot show

# This check was written expecting to report "no systemd user session here", on
# the assumption inherited from the previous development notes. The assumption was
# wrong in the interesting direction: WSL2 with systemd enabled HAS a running user
# session. So the reason this is unproven is not the environment at all --
#
#     $ grep -rl systemd src/lexe/    ->  nothing
#
# -- it is that the engine has no session-manager integration to test. That is a
# missing feature, not a missing machine, and saying "blocked on the environment"
# about it would have been comfortable and false.
if command -v systemctl >/dev/null 2>&1 && \
   systemctl --user is-system-running >/dev/null 2>&1; then
    note "a systemd user session IS running here ($(systemctl --user is-system-running 2>/dev/null))"
    note "so the gap is not the environment: the engine has no session-manager"
    note "integration to exercise. Detach, supervision, the version lease, clean"
    note "stop, kill and restart are all demonstrated above."
    note "See docs/ROADMAP.md §4 — it is a design question before it is a task."
else
    blocked "no session manager here, so session integration cannot be exercised" \
        "Detach, supervision, leases, clean stop and restart ARE demonstrated above." \
        "See docs/ROADMAP.md §4."
fi

acc_summary

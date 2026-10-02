#!/usr/bin/env bash
# scripts/arm-worker.sh — run .LEXE's test levels on the physical AArch64 worker.
#
#   scripts/arm-worker.sh probe            what is reachable, and what is not
#   scripts/arm-worker.sh sync [<commit>]  put an exact commit on the worker
#   scripts/arm-worker.sh build            configure + build there, bounded
#   scripts/arm-worker.sh levels [0..5]    run test levels, structured results
#   scripts/arm-worker.sh all [<commit>]   sync + build + levels
#
# This is a test RUNNER, not a CI platform. It does one thing: put a known
# commit on one known machine, build it there, run levels, and bring back
# results that say which machine and which commit produced them.
#
# ---------------------------------------------------------------------------
# THE WORKER
#
# A Samsung Galaxy Tab S9 FE+ (SM-X610): Android ARM64 kernel -> Termux ->
# PRoot-Distro -> Debian 13 arm64 -> native GCC. That stack is why the evidence
# language in docs/TESTING.md §6 is careful. What this machine proves is:
#
#   ".LEXE builds and executes natively on physical AArch64 hardware under
#    Debian arm64 running through PRoot on Android."
#
# It does NOT prove a conventional ARM64 Linux desktop host. PRoot emulates
# chroot in userspace via ptrace; it does not provide user namespaces, and
# bubblewrap needs those. So the sandbox levels are expected to be BLOCKED
# here, and BLOCKED is a result -- it is reported with its measured reason and
# never quietly folded into SKIP.
#
# ---------------------------------------------------------------------------
# TRANSPORT, AND WHY IT IS SSH RATHER THAN ADB
#
# ADB reaches Android as uid 2000 (`shell`), which is MEASURABLY unable to read
# Termux's files: `ls /data/data/` is "Permission denied" without root, and root
# is out of scope. So adb alone cannot execute anything inside the Debian
# environment. It can still move BYTES -- /sdcard is writable by uid 2000 --
# which is how the commit gets across.
#
#   bytes   : adb push  ->  /sdcard  ->  read from Termux
#   commands: ssh       ->  Termux sshd on 8022, via `adb forward`
#
# Nothing is exposed off-device: `adb forward` tunnels over USB, so sshd is
# reachable only from this host. No Android setting is weakened beyond the USB
# debugging already authorized, and no partition is touched.
#
# ---------------------------------------------------------------------------
# COMMIT PROVENANCE, WITHOUT A NETWORK
#
# The worker has no route back to this machine's git. Rather than copying a
# working tree -- which would make "which commit produced this evidence?"
# unanswerable, the exact failure docs/TESTING.md §1.6 exists to prevent -- the
# commit travels as a `git bundle`. A bundle is a verifiable pack: the worker
# fetches from it and ends up on that precise SHA or fails. Evidence returned
# from here always names the SHA the worker actually had checked out, read back
# from the worker rather than assumed from this side.
#
# ---------------------------------------------------------------------------
# RESOURCE POLICY (docs/TESTING.md §10)
#
# The policy binds BOTH machines and is not divided per-agent. On the tablet it
# binds harder: it is passively cooled and on battery, so thermal throttling
# makes a too-parallel build slower AND less trustworthy as a timing sample.
# Default concurrency here is 2, deliberately below the x86-64 default, and is
# overridable only downward in spirit -- raise it and you own the measurement.

set -uo pipefail

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# --------------------------------------------------------------- configuration
ARM_PORT="${LEXE_ARM_PORT:-8022}"
ARM_USER="${LEXE_ARM_USER:-u0_a248}"
ARM_KEY="${LEXE_ARM_KEY:-$HOME/.ssh/lexe_arm_worker}"
# Key-only, and deliberately so: BatchMode plus PasswordAuthentication=no means
# an unattended run FAILS instead of blocking on a prompt nobody will answer,
# and no password can be typed, logged, or captured into an evidence file.
# A FUNCTION, not a string: the key path on the development host contains a
# space ("Bennyt 2"), and an unquoted string of options word-split it into
# "/c/Users/Bennyt" and a "hostname" -- the probe then reported the worker
# unreachable while the device and the forward were both fine.
arm_ssh() {
    if [[ -n "${LEXE_ARM_SSH:-}" ]]; then $LEXE_ARM_SSH "$@"; return; fi
    ssh -p "$ARM_PORT" -i "$ARM_KEY" -o IdentitiesOnly=yes         -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no         -o BatchMode=yes -o StrictHostKeyChecking=accept-new         -o ConnectTimeout=10 "$ARM_USER@127.0.0.1" "$@"
}
ARM_JOBS="${LEXE_ARM_JOBS:-2}"           # tablet: start low, thermal headroom
ARM_WORK="${LEXE_ARM_WORK:-\$HOME/lexe-arm}"   # expanded ON the worker
ARM_DISTRO="${LEXE_ARM_DISTRO:-debian}"  # proot-distro name
EVIDENCE="${LEXE_ARM_EVIDENCE:-$REPO/../lexe-arm-evidence}"

C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_WARN=$'\033[33m'; C_OFF=$'\033[0m'
[[ -t 1 ]] || { C_OK=""; C_BAD=""; C_WARN=""; C_OFF=""; }

say()   { printf '%s\n' "$*"; }
ok()    { printf '  %sPASS%s  %s\n' "$C_OK" "$C_OFF" "$*"; }
bad()   { printf '  %sFAIL%s  %s\n' "$C_BAD" "$C_OFF" "$*"; }
block() { printf '  %sBLOCKED%s  %s\n' "$C_WARN" "$C_OFF" "$*"; }
infra() { printf '  %sINFRASTRUCTURE%s  %s\n' "$C_BAD" "$C_OFF" "$*"; }

# Run a command inside the Debian guest on the worker.
#
# proot-distro login runs the guest; --shared-tmp keeps /tmp usable. The
# command is passed to `sh -c`, so the CALLER must quote for the guest shell.
arm_guest() {
    arm_ssh "proot-distro login $ARM_DISTRO --shared-tmp -- /bin/sh -c $(printf '%q' "$1")" 2>&1
}

# Run a command in Termux itself (outside the guest).
arm_termux() { arm_ssh "$1" 2>&1; }

# ------------------------------------------------------------------ preflight
#
# Every reachability failure below is reported as INFRASTRUCTURE, never as a
# test result and never as SKIP. A runner that cannot reach its worker has not
# tested anything, and must not be able to report that it did.
cmd_probe() {
    say "== ARM worker reachability =="
    local failed=0

    if ! command -v adb >/dev/null 2>&1; then
        infra "adb is not on PATH; cannot reach the device at all"
        return 1
    fi

    local devline
    devline="$(adb devices | awk 'NR>1 && NF {print; exit}')"
    if [[ -z "$devline" ]]; then
        infra "no device attached (adb devices is empty)"
        return 1
    fi
    case "$devline" in
        *unauthorized*)
            infra "device is UNAUTHORIZED -- accept the USB-debugging prompt on the tablet"
            return 1 ;;
        *offline*)
            infra "device is offline -- replug, or restart adb"
            return 1 ;;
    esac
    ok "device attached: $devline"

    local model arch
    model="$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
    arch="$(adb shell uname -m 2>/dev/null | tr -d '\r')"
    ok "android: model=$model kernel-arch=$arch"
    [[ "$arch" == "aarch64" ]] || { bad "kernel is not aarch64; this worker is not what we think"; failed=1; }

    # Forward the ssh port over USB. Idempotent.
    if adb forward "tcp:$ARM_PORT" "tcp:$ARM_PORT" >/dev/null 2>&1; then
        ok "adb forward tcp:$ARM_PORT established (USB only; nothing exposed off-device)"
    else
        infra "could not adb-forward tcp:$ARM_PORT"
        return 1
    fi

    local hello
    hello="$(arm_ssh 'echo TERMUX_OK; uname -m' 2>&1)"
    if [[ "$hello" != *TERMUX_OK* ]]; then
        infra "ssh to Termux failed. In Termux: pkg install openssh && passwd && sshd"
        printf '        transport said: %s\n' "$(printf '%s' "$hello" | head -2 | tr '\n' ' ')"
        return 1
    fi
    ok "termux ssh: reachable ($(printf '%s' "$hello" | tail -1))"

    local guest
    guest="$(arm_guest 'echo GUEST_OK; uname -m; . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"; dpkg --print-architecture 2>/dev/null')"
    if [[ "$guest" != *GUEST_OK* ]]; then
        infra "proot-distro guest '$ARM_DISTRO' did not start"
        printf '        guest said: %s\n' "$(printf '%s' "$guest" | head -2 | tr '\n' ' ')"
        return 1
    fi
    ok "debian guest: $(printf '%s' "$guest" | sed -n '2,4p' | tr '\n' ' ')"

    local tools
    tools="$(arm_guest 'for t in git cmake g++ make file readelf sha256sum; do printf "%s=%s " "$t" "$(command -v $t >/dev/null 2>&1 && echo yes || echo NO)"; done; echo')"
    say "  toolchain: $tools"
    [[ "$tools" == *"g++=NO"* || "$tools" == *"cmake=NO"* ]] && {
        block "guest is missing a toolchain component -- apt install build-essential cmake git file binutils"
        failed=1
    }

    return "$failed"
}

# ----------------------------------------------------------------- commit sync
cmd_sync() {
    local commit="${1:-HEAD}"
    local sha; sha="$(git -C "$REPO" rev-parse "$commit")" || { infra "no such commit: $commit"; return 1; }

    say "== syncing $sha to the worker =="

    # Refuse to ship evidence whose source we cannot name. A dirty tree means
    # the bundle and the working tree disagree, and every result afterwards
    # would be attributed to a commit that does not describe what ran.
    if [[ -n "$(git -C "$REPO" status --porcelain)" ]]; then
        infra "working tree is dirty; commit or stash first so the worker's commit is nameable"
        return 1
    fi

    local bundle="$REPO/../lexe-sync.bundle"
    git -C "$REPO" bundle create "$bundle" "$sha" --branches=HEAD >/dev/null 2>&1 \
        || git -C "$REPO" bundle create "$bundle" "$sha" >/dev/null 2>&1 \
        || { infra "git bundle create failed"; return 1; }
    ok "bundle: $(du -h "$bundle" | cut -f1)"

    adb push "$bundle" /sdcard/lexe-sync.bundle >/dev/null 2>&1 \
        || { infra "adb push to /sdcard failed"; return 1; }
    ok "pushed to /sdcard"

    # Termux reads /sdcard only after termux-setup-storage; ~/storage/shared is
    # the symlink it creates. Try both, and say which worked.
    local moved
    moved="$(arm_termux 'p=""; for c in "$HOME/storage/shared/lexe-sync.bundle" /sdcard/lexe-sync.bundle; do [ -r "$c" ] && p="$c" && break; done; if [ -z "$p" ]; then echo NO_READABLE_COPY; else cp "$p" "$HOME/lexe-sync.bundle" && echo "COPIED_FROM=$p"; fi')"
    if [[ "$moved" == *NO_READABLE_COPY* ]]; then
        infra "Termux cannot read /sdcard -- run termux-setup-storage in Termux and grant the permission"
        return 1
    fi
    ok "termux: ${moved}"

    local out
    out="$(arm_guest "set -e
mkdir -p $ARM_WORK
cd $ARM_WORK
if [ ! -d repo/.git ]; then git init -q repo; fi
cd repo
git config user.email arm@worker.local
git config user.name  'ARM Worker'
cp /data/data/com.termux/files/home/lexe-sync.bundle ./sync.bundle 2>/dev/null || cp \$HOME/../usr/../home/lexe-sync.bundle ./sync.bundle 2>/dev/null || true
if [ ! -f ./sync.bundle ]; then echo NO_BUNDLE_IN_GUEST; exit 1; fi
git fetch -q ./sync.bundle $sha 2>&1 | tail -2 || true
git checkout -q --detach $sha
echo CHECKED_OUT=\$(git rev-parse HEAD)")"

    if [[ "$out" == *NO_BUNDLE_IN_GUEST* ]]; then
        infra "the bundle did not reach the Debian guest (Termux \$HOME is not visible from the guest)"
        printf '        guest said: %s\n' "$(printf '%s' "$out" | head -3 | tr '\n' ' ')"
        return 1
    fi
    local got; got="$(printf '%s' "$out" | sed -n 's/^CHECKED_OUT=//p' | tail -1)"
    if [[ "$got" != "$sha" ]]; then
        infra "worker is on '$got', not the requested $sha"
        printf '        guest said: %s\n' "$(printf '%s' "$out" | tail -4 | tr '\n' ' ')"
        return 1
    fi
    ok "worker checked out $got  (read back from the worker, not assumed)"
    printf '%s' "$got" > "$EVIDENCE/arm-commit.txt" 2>/dev/null || true
    return 0
}

# ---------------------------------------------------------------------- build
cmd_build() {
    say "== native ARM64 build (jobs=$ARM_JOBS) =="
    mkdir -p "$EVIDENCE"
    local out
    out="$(arm_guest "set -e
cd $ARM_WORK/repo
cmake -S . -B build-arm64 -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null 2>&1 || { echo CONFIGURE_FAILED; exit 1; }
cmake --build build-arm64 -j $ARM_JOBS 2>&1 | tail -5
echo BUILD_RC=\$?
for b in build-arm64/lexe build-arm64/lexe_tests; do
  if [ -x \"\$b\" ]; then echo \"ARTIFACT \$b \$(file -b \$b | cut -c1-60)\"; else echo \"ARTIFACT \$b MISSING\"; fi
done")"
    printf '%s\n' "$out" | sed 's/^/    /'
    printf '%s\n' "$out" > "$EVIDENCE/arm-build.txt"

    if [[ "$out" == *CONFIGURE_FAILED* ]]; then infra "cmake configure failed on the worker"; return 1; fi
    if [[ "$out" == *"lexe_tests MISSING"* ]]; then bad "lexe_tests was not produced"; return 1; fi
    # The artifact must actually be AArch64 -- a build that silently produced an
    # x86-64 binary would otherwise read as a successful ARM build.
    if [[ "$out" != *"ARM aarch64"* ]]; then
        bad "artifacts are not ARM aarch64 ELF; this is not second-ISA evidence"
        return 1
    fi
    ok "native AArch64 artifacts produced"
    return 0
}

# --------------------------------------------------------------------- levels
#
# Level membership is explicit. Any suite the binary reports that is NOT
# mapped here is printed as UNMAPPED rather than quietly run or quietly
# dropped -- a mapping that silently drifts is the "a check cannot detect what
# it holds constant" failure wearing a config file.
L1_SUITES="crypto,ed25519_strict,json_strict,manifest,elf,pe,package,limits,tux32,depengine,compat,paths,architecture,envelope-seams,payload_role,presentation,runtime-profile,launch-cost,execution-architecture,buildreport,permissions,settings,http,tux32-verify,ui,util,verify,version,versioncmp"
L2_SUITES="installer,transaction,registry,storage,crash_recovery,repair-after-rollback,trust,trust-adversarial,trust-lifecycle,hostile_packages,invariants,install_reporting,no_execution,health_check,lock,concurrent-state,cli,cli_apps,cli_inspect,cli_e2e,cli_sdk_verify,cli_ux,builder,security-boundary,integration-durability,uninstall_paths,updater"
L3_SUITES="launcher,hostbuild,race"
L4_SUITES="isolation,isolation_linux,etc_surface,desktop,session-units,gui"
L5_SUITES="proton"

# Every suite the binary has must belong to a level.
#
# This is not bookkeeping. `-ts=a,b,c` silently runs nothing for a name that
# does not exist, and a suite absent from every list is silently never run --
# so "levels 0-3 passed on ARM" would be a claim about a subset nobody
# enumerated, shrinking quietly as the suite grows. Written as a runtime check
# rather than a one-off, because a one-off audit is true on the day it is run.
#
# It found eight on its first execution -- tux32-verify, ui, uninstall_paths,
# updater, util, verify, version, versioncmp -- in a mapping written the same
# afternoon.
audit_level_mapping() {
    local mapped
    mapped="$(printf '%s\n%s\n%s\n%s\n%s\n' "$L1_SUITES" "$L2_SUITES" "$L3_SUITES" \
                 "$L4_SUITES" "$L5_SUITES" | tr ',' '\n' | grep -v '^$' | sort -u)"
    local have
    have="$(arm_guest "cd $ARM_WORK/repo && ./build-arm64/lexe_tests --list-test-suites 2>/dev/null" \
            | sed -n '3,$p' | grep -v '^\[doctest\]' | grep -v '^=*$' \
            | sed 's/[[:space:]]*$//' | grep -v '^$' | sort -u)"
    [[ -n "$have" ]] || { block "could not list suites on the worker; level coverage UNVERIFIED"; return 1; }

    local unmapped stale
    unmapped="$(comm -23 <(printf '%s\n' "$have") <(printf '%s\n' "$mapped"))"
    stale="$(comm -13 <(printf '%s\n' "$have") <(printf '%s\n' "$mapped"))"

    if [[ -n "$unmapped" ]]; then
        bad "suites belong to no level and would never run here:"
        printf '%s\n' "$unmapped" | sed 's/^/          /'
        return 1
    fi
    if [[ -n "$stale" ]]; then
        block "level lists name suites the binary does not have (they match nothing):"
        printf '%s\n' "$stale" | sed 's/^/          /'
    fi
    ok "level mapping covers every suite the worker's binary reports"
    return 0
}

run_level_suites() {  # <level> <comma-list>
    local level="$1" suites="$2"
    local out
    out="$(arm_guest "cd $ARM_WORK/repo && ./build-arm64/lexe_tests --no-colors -ts=$suites 2>&1 | tail -4")"
    printf '%s\n' "$out" | sed 's/^/      /'
    printf '%s\n' "$out" >> "$EVIDENCE/arm-levels.txt"
    if [[ "$out" == *"Status: SUCCESS!"* ]]; then ok "LEVEL $level"; return 0
    elif [[ "$out" == *"test cases:"* ]]; then bad "LEVEL $level"; return 1
    else infra "LEVEL $level produced no doctest summary (binary missing or crashed on start)"; return 2; fi
}

cmd_levels() {
    local want="${1:-5}"
    mkdir -p "$EVIDENCE"; : > "$EVIDENCE/arm-levels.txt"
    say "== ARM test levels (through $want) =="

    # LEVEL 0 -- environment/artifact sanity and CLI startup.
    say "  -- LEVEL 0: environment, artifact format, CLI startup"
    local l0
    l0="$(arm_guest "cd $ARM_WORK/repo
echo KERNEL=\$(uname -m)
echo DPKG=\$(dpkg --print-architecture 2>/dev/null)
echo ELF=\$(file -b build-arm64/lexe | cut -c1-55)
echo READELF=\$(readelf -h build-arm64/lexe 2>/dev/null | awk '/Machine:/{print \$2, \$3}')
./build-arm64/lexe version >/dev/null 2>&1 && echo CLI_STARTS=yes || echo CLI_STARTS=no")"
    printf '%s\n' "$l0" | sed 's/^/      /'
    printf '%s\n' "$l0" >> "$EVIDENCE/arm-levels.txt"
    if [[ "$l0" == *"CLI_STARTS=yes"* && "$l0" == *"KERNEL=aarch64"* && "$l0" == *aarch64* ]]; then
        ok "LEVEL 0"
    else
        bad "LEVEL 0 -- the worker is not a working AArch64 .LEXE host"
        return 1
    fi
    [[ "$want" -ge 1 ]] || return 0

    # Before claiming a level passed, establish that the levels cover the suite.
    audit_level_mapping || true

    say "  -- LEVEL 1: pure unit logic (parsers, format, crypto)"
    run_level_suites 1 "$L1_SUITES"; local r1=$?
    [[ "$want" -ge 2 ]] || return $r1

    say "  -- LEVEL 2: package/install lifecycle (no host isolation needed)"
    run_level_suites 2 "$L2_SUITES"; local r2=$?
    [[ "$want" -ge 3 ]] || return $(( r1 || r2 ))

    say "  -- LEVEL 3: launcher and process behaviour"
    run_level_suites 3 "$L3_SUITES"; local r3=$?
    [[ "$want" -ge 4 ]] || return $(( r1 || r2 || r3 ))

    # LEVEL 4 -- expected BLOCKED under PRoot, but MEASURED rather than assumed.
    say "  -- LEVEL 4: sandbox / namespace / desktop integration"
    local ns
    ns="$(arm_guest "command -v bwrap >/dev/null 2>&1 && echo BWRAP=yes || echo BWRAP=no
unshare --user --pid true 2>&1 | head -1 | sed 's/^/USERNS=/'")"
    printf '%s\n' "$ns" | sed 's/^/      /'
    if [[ "$ns" == *"BWRAP=no"* ]]; then
        block "LEVEL 4: bubblewrap is absent in the guest. PRoot emulates chroot via ptrace and provides no user namespaces, which bwrap requires. This is an environment limit of the worker, not a .LEXE result -- the sandbox levels are untested here, NOT passing."
    else
        run_level_suites 4 "$L4_SUITES"
    fi
    [[ "$want" -ge 5 ]] || return 0

    say "  -- LEVEL 5: compatibility runtimes"
    block "LEVEL 5: Wine/Proton are x86-64 chains; on an AArch64 worker they would require ISA translation, which §20 forbids as a native path. Not applicable here, and not evidence either way."
    return 0
}

cmd_all() {
    cmd_probe   || return 1
    cmd_sync "${1:-HEAD}" || return 1
    cmd_build   || return 1
    cmd_levels 5
}

mkdir -p "$EVIDENCE" 2>/dev/null || true
case "${1:-probe}" in
    probe)  cmd_probe ;;
    sync)   shift; cmd_sync "${1:-HEAD}" ;;
    build)  cmd_build ;;
    levels) shift; cmd_levels "${1:-5}" ;;
    all)    shift; cmd_all "${1:-HEAD}" ;;
    *)      sed -n '2,10p' "$0"; exit 2 ;;
esac

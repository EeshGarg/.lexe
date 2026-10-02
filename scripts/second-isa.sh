#!/usr/bin/env bash
# scripts/second-isa.sh — one signed portable-source package, two ISAs.
#
#   scripts/second-isa.sh build     make the package, record its identity
#   scripts/second-isa.sh local     materialize it on THIS host (x86-64)
#   scripts/second-isa.sh remote    materialize it on the ARM worker
#   scripts/second-isa.sh compare   put the two records side by side
#   scripts/second-isa.sh all       all four, in order
#
# THE CLAIM THIS IS BUILT TO SUPPORT, and its exact limits:
#
#   ".LEXE portable source materializes and executes native products on both
#    x86-64 Linux and physical AArch64 hardware."
#
# It does NOT support ".LEXE is supported on any ARM64 Linux desktop". The ARM
# host is Debian arm64 under PRoot on Android, and PRoot is not a namespace
# sandbox. That distinction is kept in the evidence itself rather than left to
# whoever reads it later.
#
# WHAT MAKES THIS EVIDENCE RATHER THAN A DEMO:
#
#   * The package bytes must be IDENTICAL. Both hosts hash the file
#     independently, with their own sha256sum, and the hashes are compared at
#     the end. A package rebuilt per host would prove nothing at all -- two
#     different inputs producing two different outputs is not a finding.
#
#   * The products must DIFFER, and differ in the right way. Same input, two
#     machines, and if the resulting ELFs had the same architecture then one of
#     them did not compile locally. `file` and `readelf -h` are both recorded
#     because they read the header independently of each other and of .LEXE.
#
#   * Both products must RUN. An AArch64 ELF that exists but cannot execute is
#     a cross-compilation artifact, not a materialization.
#
# Every fact is recorded as a line in a per-host record, so the comparison is
# mechanical rather than a matter of reading two logs and squinting.

set -uo pipefail

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
EV="${LEXE_ISA_EVIDENCE:-$REPO/../lexe-isa-evidence}"
LEXE="${LEXE_BIN:-$REPO/build/lexe}"
ARM_PORT="${LEXE_ARM_PORT:-8022}"
ARM_USER="${LEXE_ARM_USER:-u0_a248}"
ARM_KEY="${LEXE_ARM_KEY:-$HOME/.ssh/lexe_arm_worker}"
# A function, not a string, for the same reason as in arm-worker.sh: the key
# path can contain a space. Key-only and batch, so an unattended run fails
# instead of waiting for a password.
arm_ssh() {
    ssh -p "$ARM_PORT" -i "$ARM_KEY" -o IdentitiesOnly=yes \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 "$ARM_USER@127.0.0.1" "$@"
}
ARM_WORK="\$HOME/lexe-isa"
ARM_DISTRO="${LEXE_ARM_DISTRO:-debian}"
# The runtime that scripts/arm-worker.sh synced and built (expanded ON the worker).
ARM_LEXE="${LEXE_ARM_LEXE:-\$HOME/lexe-arm/repo/build-arm64/lexe}"

PKG="$EV/second-isa.lexe"
KEY="$EV/second-isa-key.json"

say()  { printf '%s\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; }
info() { printf '        %s\n' "$*"; }

arm_guest() { arm_ssh "proot-distro login $ARM_DISTRO --shared-tmp -- /bin/sh -c $(printf '%q' "$1")" 2>&1; }

# ------------------------------------------------------------------ the package
#
# Deliberately a C program that PRINTS FACTS ABOUT ITS OWN BUILD. A portable
# package proves its point only if the thing that comes out the far end can be
# interrogated, and the cheapest interrogation is the program telling you what
# compiler produced it and what machine it thinks it is on.
cmd_build() {
    say "== building one signed portable-source package =="
    mkdir -p "$EV"
    local proj="$EV/project"
    rm -rf "$proj"
    mkdir -p "$proj/payload/src" "$proj/payload/bin"

    cat > "$proj/payload/src/main.c" <<'EOF'
#include <stdio.h>
int main(void) {
    printf("SECOND_ISA_PRODUCT\n");
#if defined(__x86_64__)
    printf("COMPILED_FOR=x86_64\n");
#elif defined(__aarch64__)
    printf("COMPILED_FOR=aarch64\n");
#else
    printf("COMPILED_FOR=other\n");
#endif
#if defined(__GNUC__)
    printf("COMPILER=gcc-like %d.%d\n", __GNUC__, __GNUC_MINOR__);
#endif
    printf("POINTER_BITS=%zu\n", sizeof(void*) * 8);
    return 0;
}
EOF

    cat > "$proj/lexe.json" <<'EOF'
{
  "lexeVersion": "0.1",
  "id": "org.lexe.secondisa",
  "name": "Second ISA Probe",
  "version": "1.0.0",
  "publisher": { "name": "LEXE Evidence", "publicKey": "AUTO" },
  "applicationType": "portable",
  "architectures": ["x86_64", "aarch64"],
  "entrypoint": { "executable": "bin/app", "arguments": [] },
  "launch": { "mode": "console" },
  "install": { "scope": "user", "mode": "bundled" },
  "build": { "system": "command",
             "sourceDir": "src",
             "command": ["cc", "-O2", "-o", "bin/app", "src/main.c"],
             "toolchain": ["cc"] },
  "permissions": []
}
EOF

    "$LEXE" keygen "$KEY" >/dev/null || { bad "keygen"; return 1; }
    "$LEXE" build "$proj" -o "$PKG" --key "$KEY" >/dev/null || { bad "lexe build"; return 1; }

    local h; h="$(sha256sum "$PKG" | awk '{print $1}')"
    printf '%s\n' "$h" > "$EV/package.sha256"
    ok "package built"
    info "path   $PKG"
    info "sha256 $h"
    info "bytes  $(stat -c%s "$PKG")"
    return 0
}

# ------------------------------------------------------------- materialization
#
# `record_here` runs on whichever machine it is invoked on; the remote side
# ships this same function body over ssh so both hosts answer the SAME
# questions in the same order. Two hosts answering differently-worded questions
# is how comparisons quietly stop comparing.
record_here() {  # record_here <lexe-binary> <package> <out-file>
    local lexe="$1" pkg="$2" out="$3"
    local id=org.lexe.secondisa
    : > "$out"
    {
        printf 'HOST_UNAME=%s\n' "$(uname -m)"
        printf 'HOST_OS=%s\n' "$(uname -s)"
        printf 'PACKAGE_SHA256=%s\n' "$(sha256sum "$pkg" | awk '{print $1}')"
        printf 'PACKAGE_BYTES=%s\n' "$(stat -c%s "$pkg")"
        printf 'CC_VERSION=%s\n' "$(cc --version 2>/dev/null | head -1)"
        printf 'LEXE_VERSION=%s\n' "$("$lexe" version 2>/dev/null | head -1)"
        printf 'LEXE_BIN_SHA256=%s\n' "$(sha256sum "$lexe" | awk '{print $1}')"
        printf 'LEXE_BIN_FILE=%s\n' "$(file -b "$lexe" | cut -c1-70)"
        # The commit the runtime was built from, as the host's own git sees it.
        printf 'GIT_SHA=%s\n' "$(git -C "$(dirname "$lexe")/.." rev-parse HEAD 2>/dev/null)"
        printf 'GIT_DIRTY_FILES=%s\n' "$(git -C "$(dirname "$lexe")/.." status --porcelain 2>/dev/null | wc -l)"
        printf 'BUILD_RECIPE=cc -O2 -o bin/app src/main.c (from the signed manifest)\n'
    } >> "$out"

    # Signature identity, read by this host's runtime from these bytes.
    "$lexe" verify "$pkg" > "$out.verify" 2>&1
    printf 'VERIFY_RC=%s\n' "$?" >> "$out"
    sed 's/^/VERIFY_OUT /' "$out.verify" >> "$out"

    "$lexe" install "$pkg" --yes --trust --approve-compile > "$out.install" 2> "$out.install.err"
    printf 'INSTALL_RC=%s\n' "$?" >> "$out"
    sed 's/^/INSTALL_STDERR /' "$out.install.err" >> "$out"

    # The product: where the runtime put it, what it is, and whether it runs.
    local prod
    prod="$(find "${LEXE_HOME:-$HOME/.local/share/lexe}/apps/$id" -type f -name app 2>/dev/null | head -1)"
    if [ -z "$prod" ]; then
        printf 'PRODUCT=ABSENT\n' >> "$out"
        return 1
    fi
    {
        printf 'PRODUCT_PATH=%s\n' "$prod"
        printf 'PRODUCT_SHA256=%s\n' "$(sha256sum "$prod" | awk '{print $1}')"
        printf 'PRODUCT_FILE=%s\n' "$(file -b "$prod" | cut -c1-70)"
        printf 'PRODUCT_READELF_MACHINE=%s\n' \
            "$(readelf -h "$prod" 2>/dev/null | awk -F: '/Machine:/{gsub(/^ +/,"",$2); print $2}')"
        printf 'PRODUCT_READELF_CLASS=%s\n' \
            "$(readelf -h "$prod" 2>/dev/null | awk -F: '/Class:/{gsub(/^ +/,"",$2); print $2}')"
    } >> "$out"
    readelf -h "$prod" 2>&1 | sed 's/^/READELF_H /' >> "$out"
    local bj
    bj="$(find "${LEXE_HOME:-$HOME/.local/share/lexe}" -name build.json 2>/dev/null | head -1)"
    printf 'BUILD_JSON_PATH=%s\n' "${bj:-ABSENT}" >> "$out"
    [ -n "$bj" ] && sed 's/^/BUILD_JSON /' "$bj" >> "$out"

    "$lexe" run "$id" > "$out.run" 2> "$out.run.err"
    printf 'RUN_RC=%s\n' "$?" >> "$out"
    sed 's/^/RUN_OUT /' "$out.run" >> "$out"
    sed 's/^/RUN_STDERR /' "$out.run.err" >> "$out"
    return 0
}

cmd_local() {
    say "== materializing on THIS host =="
    [ -f "$PKG" ] || { bad "no package; run 'build' first"; return 1; }
    local home="$EV/home-x86"
    rm -rf "$home"; mkdir -p "$home"
    LEXE_HOME="$home" record_here "$LEXE" "$PKG" "$EV/record-x86_64.txt"
    sed 's/^/    /' "$EV/record-x86_64.txt"
}

cmd_remote() {
    say "== materializing on the ARM worker =="
    [ -f "$PKG" ] || { bad "no package; run 'build' first"; return 1; }

    if ! arm_ssh 'echo ok' >/dev/null 2>&1; then
        bad "INFRASTRUCTURE: no key-based ssh to the worker"
        info "adb forward tcp:$ARM_PORT tcp:$ARM_PORT, and install the dev public key"
        return 1
    fi

    # The package travels as BYTES over the ssh channel and is hashed again on
    # arrival, by the worker's own sha256sum. Any difference invalidates the
    # whole experiment, so it is checked rather than assumed.
    local local_sha; local_sha="$(sha256sum "$PKG" | awk '{print $1}')"
    arm_ssh 'cat > "$HOME/second-isa.lexe"' < "$PKG" || { bad "INFRASTRUCTURE: transfer"; return 1; }

    local remote_sha
    remote_sha="$(arm_ssh 'sha256sum $HOME/second-isa.lexe' 2>/dev/null | awk '{print $1}')"
    if [ "$remote_sha" != "$local_sha" ]; then
        bad "the package changed in transit -- the experiment is void"
        info "local  $local_sha"
        info "remote $remote_sha"
        return 1
    fi
    ok "package bytes identical on both machines ($remote_sha)"

    # Hand the guest the same questions, answered by its own tools.
    local script
    script="$(declare -f record_here)
export LEXE_HOME=$ARM_WORK/home
mkdir -p \$LEXE_HOME
cp /data/data/com.termux/files/home/second-isa.lexe $ARM_WORK/pkg.lexe 2>/dev/null || cp \$HOME/second-isa.lexe $ARM_WORK/pkg.lexe
record_here $ARM_LEXE $ARM_WORK/pkg.lexe $ARM_WORK/record.txt
cat $ARM_WORK/record.txt"
    arm_guest "mkdir -p $ARM_WORK" >/dev/null 2>&1
    arm_guest "$script" | tee "$EV/record-aarch64.txt" | sed 's/^/    /'
}

cmd_compare() {
    say "== the comparison =="
    local x="$EV/record-x86_64.txt" a="$EV/record-aarch64.txt"
    [ -f "$x" ] && [ -f "$a" ] || { bad "need both records; run local and remote first"; return 1; }

    get() { sed -n "s/^$2=//p" "$1" | head -1; }

    local xp ap xm am xr ar
    xp="$(get "$x" PACKAGE_SHA256)"; ap="$(get "$a" PACKAGE_SHA256)"
    xm="$(get "$x" PRODUCT_READELF_MACHINE)"; am="$(get "$a" PRODUCT_READELF_MACHINE)"
    xr="$(get "$x" RUN_RC)"; ar="$(get "$a" RUN_RC)"

    # 1. Same authenticated input.
    if [ -n "$xp" ] && [ "$xp" = "$ap" ]; then ok "identical package sha256 on both hosts: $xp"
    else bad "package hashes differ ($xp vs $ap) -- not the same input"; fi

    # 1b. Same signer, as each host's own runtime reports it from the bytes.
    local xv av
    # The 'Verifying <path>' line names a host-local path; everything after it must match.
    xv="$(sed -n 's/^VERIFY_OUT //p' "$x" | grep -v '^Verifying ')"; av="$(sed -n 's/^VERIFY_OUT //p' "$a" | grep -v '^Verifying ')"
    if [ "$(get "$x" VERIFY_RC)" = 0 ] && [ "$(get "$a" VERIFY_RC)" = 0 ] && [ -n "$xv" ] && [ "$xv" = "$av" ]; then
        ok "signature verified on both hosts, identical verify report"
    else
        bad "signature report differs or failed (rc $(get "$x" VERIFY_RC) vs $(get "$a" VERIFY_RC))"
    fi

    # 2. Different products, and different in the ISA.
    if [ -n "$xm" ] && [ -n "$am" ] && [ "$xm" != "$am" ]; then
        ok "products target different machines: x86 host -> '$xm', ARM host -> '$am'"
    else
        bad "product machine did not differ ('$xm' vs '$am') -- one host did not compile locally"
    fi

    # 3. Both ran.
    [ "$xr" = "0" ] && ok "x86-64 product executed (rc=0)" || bad "x86-64 product rc=$xr"
    [ "$ar" = "0" ] && ok "AArch64 product executed (rc=0)" || bad "AArch64 product rc=$ar"

    say ""
    say "  the claim this supports:"
    say "    .LEXE portable source materializes and executes native products on"
    say "    both x86-64 Linux and physical AArch64 hardware (Debian arm64 under"
    say "    PRoot on Android). It does NOT establish support for arbitrary"
    say "    ARM64 Linux desktops."
}

mkdir -p "$EV" 2>/dev/null || true
case "${1:-all}" in
    build)   cmd_build ;;
    local)   cmd_local ;;
    remote)  cmd_remote ;;
    compare) cmd_compare ;;
    all)     cmd_build && cmd_local; cmd_remote; cmd_compare ;;
    *)       sed -n '2,8p' "$0"; exit 2 ;;
esac

#!/bin/sh
# =============================================================================
# Tux32 Core 1 — cross-distribution portability proof.
#
# This script demonstrates the milestone invariant end to end: ONE unchanged,
# dynamically linked, signed .lexe artifact traverses the real build,
# verification, packaging, installation, isolation and launch path across a
# genuine compatibility boundary — from a NEWER build host to an OLDER
# conforming runtime — and the build host does NOT silently become the
# compatibility target.
#
# Boundary (real, not simulated):
#   * newer development host : ubuntu:24.04  (glibc 2.39)
#   * Core 1 sysroot         : debian:11     (glibc 2.31 == the ceiling)
#   * older conforming runtime : debian:12   (glibc 2.36, merged-usr, modern
#                                              bubblewrap — a DIFFERENT distro,
#                                              older than the build host)
#
# It proves BOTH directions:
#   A. A binary built on the newer host imports GLIBC_2.34 and is REJECTED by
#      `lexe sdk verify` (symbol-ceiling-exceeded) — the build host is not the
#      target — and that rejected binary genuinely FAILS to load on a glibc-2.31
#      host, so the check prevented a real breakage.
#   B. The SAME source, built in the Core 1 sysroot, verifies CONFORMANT, is
#      packaged + signed once, and that exact artifact installs and LAUNCHES
#      under the isolation sandbox on a fresh, older, DIFFERENT-distro host,
#      unchanged (checksum identical), its persistent data surviving launches.
#
# Requirements: a container CLI (podman by default) able to run --privileged
# (bubblewrap needs nested user namespaces). Network access only to the base
# images and the Debian/Ubuntu/PyPI package mirrors.
#
# Usage:   scripts/portability-demo.sh
# Env:     CONTAINER (default podman), SYSROOT_IMAGE (default debian:11),
#          RUNTIME_IMAGE (default debian:12), DEVHOST_IMAGE (default
#          ubuntu:24.04), WORK (default: a temp dir), KEEP_WORK=1 to keep it.
# Exit:    0 only if every assertion holds; non-zero on the first failure.
# =============================================================================
set -eu

CONTAINER="${CONTAINER:-podman}"
SYSROOT_IMAGE="${SYSROOT_IMAGE:-docker.io/library/debian:11}"   # glibc 2.31
RUNTIME_IMAGE="${RUNTIME_IMAGE:-docker.io/library/debian:12}"   # glibc 2.36, merged-usr
DEVHOST_IMAGE="${DEVHOST_IMAGE:-docker.io/library/ubuntu:24.04}" # glibc 2.39
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK="${WORK:-$(mktemp -d)}"
APP_ID="org.lexe.reference.probe"

mkdir -p "$WORK/bin"
step()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()    { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
die()   { printf '  \033[31mFAIL\033[0m %s\n' "$1" >&2; exit 1; }
cleanup() { [ "${KEEP_WORK:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT

printf 'Tux32 Core 1 portability proof\n  work dir:   %s\n  container:  %s\n' \
    "$WORK" "$CONTAINER"
printf '  sysroot:    %s (Core 1 baseline, glibc 2.31)\n' "$SYSROOT_IMAGE"
printf '  dev host:   %s (newer, glibc 2.39)\n' "$DEVHOST_IMAGE"
printf '  old runtime:%s (older conforming host)\n' "$RUNTIME_IMAGE"

# -----------------------------------------------------------------------------
step "0a  Build the runtime + a conforming app IN the Core 1 sysroot (glibc 2.31)"
# The runtime is built in the sysroot so it runs on the OLD host too (and, being
# forward-compatible, on the newer host we drive from). The reference app is
# built here so its glibc floor stays at or below the 2.31 ceiling.
if [ -x "$WORK/bin/lexe" ] && [ -x "$WORK/app-conforming/payload/bin/portable-probe" ]; then
    ok "reusing cached runtime + conforming app in $WORK"
else
  "$CONTAINER" run --rm -v "$REPO:/repo:ro" -v "$WORK:/work" "$SYSROOT_IMAGE" \
    sh -eu -c '
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null
      apt-get install -y -qq --no-install-recommends g++ make python3-pip >/dev/null
      pip3 install --quiet "cmake>=3.22,<4" ninja 2>/dev/null || pip3 install --quiet cmake ninja
      echo "  sysroot: glibc $(getconf GNU_LIBC_VERSION | awk "{print \$2}"), $(g++ --version | head -1)"
      cp -r /repo /build && cd /build
      cmake -S . -B b -G Ninja -DCMAKE_BUILD_TYPE=Release >/tmp/cfg.log 2>&1 \
        || { tail -20 /tmp/cfg.log; exit 1; }
      cmake --build b --target lexe >/tmp/bld.log 2>&1 \
        || { tail -30 /tmp/bld.log; exit 1; }
      cp b/lexe /work/bin/lexe
      # Conforming build of the reference app (in the sysroot).
      cp -r /repo/sdk/tux32-core-1/reference-app /work/app-conforming
      make -C /work/app-conforming >/tmp/app.log 2>&1 || { cat /tmp/app.log; exit 1; }
    '
  ok "built lexe + conforming reference app in the Core 1 sysroot"
fi
LEXE="$WORK/bin/lexe"
[ -x "$LEXE" ] || die "runtime binary was not produced"

# -----------------------------------------------------------------------------
step "0b  Build the SAME app on the NEWER dev host (glibc 2.39)"
"$CONTAINER" run --rm -v "$REPO:/repo:ro" -v "$WORK:/work" "$DEVHOST_IMAGE" \
  sh -eu -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends gcc make libc6-dev >/dev/null
    echo "  dev host: glibc $(getconf GNU_LIBC_VERSION | awk "{print \$2}")"
    cp -r /repo/sdk/tux32-core-1/reference-app /work/app-native
    make -C /work/app-native >/tmp/n.log 2>&1 || { cat /tmp/n.log; exit 1; }
  '
ok "built the reference app on the newer host"

# The runtime binary is portable: built in the sysroot, it runs here too.
"$LEXE" help >/dev/null 2>&1 || die "the sysroot-built runtime does not run on this host"
ok "the sysroot-built runtime runs on this (newer) host — forward compatible"

# -----------------------------------------------------------------------------
step "1  Verify the newer-host build → MUST be rejected (build host != target)"
set +e
"$LEXE" sdk verify "$WORK/app-native" --json >"$WORK/native.json" 2>&1
NATIVE_EXIT=$?
set -e
NATIVE_VERDICT=$(grep -o '"verdict": *"[^"]*"' "$WORK/native.json" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
NATIVE_GLIBC=$(grep -o '"requiredGlibc": *"[^"]*"' "$WORK/native.json" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
printf '  verdict=%s requiredGlibc=%s exit=%s\n' "$NATIVE_VERDICT" "$NATIVE_GLIBC" "$NATIVE_EXIT"
[ "$NATIVE_EXIT" = 3 ] || die "expected a non-conformant exit (3), got $NATIVE_EXIT"
[ "$NATIVE_VERDICT" = "symbol-ceiling-exceeded" ] \
    || die "expected symbol-ceiling-exceeded, got '$NATIVE_VERDICT'"
ok "the newer-host binary is refused a Core 1 claim (needs glibc $NATIVE_GLIBC > 2.31)"

# -----------------------------------------------------------------------------
step "1b  Counterfactual: that rejected binary really FAILS on a glibc-2.31 host"
# Run the newer-host binary DIRECTLY (no runtime, no sandbox) on a glibc-2.31
# host. The dynamic loader refuses it — exactly the breakage `lexe sdk verify`
# prevented from ever being packaged.
set +e
CF_OUT=$("$CONTAINER" run --rm \
    -v "$WORK/app-native/payload/bin/portable-probe:/probe:ro" \
    "$SYSROOT_IMAGE" /probe 2>&1)
CF_EXIT=$?
set -e
printf '  %s\n  exit=%s\n' "$CF_OUT" "$CF_EXIT"
[ "$CF_EXIT" != 0 ] || die "the non-conforming binary unexpectedly ran on glibc 2.31"
echo "$CF_OUT" | grep -q "GLIBC_2.34" \
    || die "expected a GLIBC_2.34 loader error, got: $CF_OUT"
ok "the loader rejects the newer-host binary on glibc 2.31 (GLIBC_2.34 not found)"

# -----------------------------------------------------------------------------
step "2  Verify the sysroot build → MUST be conformant"
set +e
"$LEXE" sdk verify "$WORK/app-conforming" --json >"$WORK/conf.json" 2>&1
CONF_EXIT=$?
set -e
CONF_VERDICT=$(grep -o '"verdict": *"[^"]*"' "$WORK/conf.json" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
CONF_GLIBC=$(grep -o '"requiredGlibc": *"[^"]*"' "$WORK/conf.json" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
printf '  verdict=%s requiredGlibc=%s exit=%s\n' "$CONF_VERDICT" "$CONF_GLIBC" "$CONF_EXIT"
[ "$CONF_EXIT" = 0 ] || die "expected a conformant exit (0), got $CONF_EXIT"
[ "$CONF_VERDICT" = "conformant" ] || die "expected conformant, got '$CONF_VERDICT'"
ok "the sysroot binary is Core 1 conformant (needs glibc $CONF_GLIBC <= 2.31)"

# -----------------------------------------------------------------------------
step "3  Package + sign the conforming app ONCE (on the dev host)"
rm -f "$WORK/key.json" "$WORK/probe.lexe" "$WORK/probe.sha256" # fresh each run
# `lexe build` fills publisher.publicKey ("AUTO") into the manifest in place;
# reset it to pristine so re-runs re-sign with the fresh key.
cp "$REPO/sdk/tux32-core-1/reference-app/lexe.json" "$WORK/app-conforming/lexe.json"
"$LEXE" keygen "$WORK/key.json" >/dev/null
"$LEXE" build "$WORK/app-conforming" -o "$WORK/probe.lexe" --key "$WORK/key.json" >/dev/null
[ -f "$WORK/probe.lexe" ] || die "lexe build produced no package"
BUILT_SHA=$(sha256sum "$WORK/probe.lexe" | awk '{print $1}')
echo "$BUILT_SHA" >"$WORK/probe.sha256"
printf '  package: probe.lexe  sha256=%s\n' "$BUILT_SHA"
ok "built and signed a single .lexe artifact"

# -----------------------------------------------------------------------------
step "4  Install + LAUNCH the UNCHANGED artifact on a fresh OLD runtime"
# A pristine, older, DIFFERENT-distro host with only the runtime + bubblewrap.
# The package is bound in read-only, so it cannot be mutated; the container
# re-checksums it, installs it, and launches it TWICE under the real isolation
# sandbox. The runtime binary was built in the glibc-2.31 sysroot, so it runs
# here too.
"$CONTAINER" run --rm --privileged \
  -v "$WORK/bin/lexe:/usr/local/bin/lexe:ro" \
  -v "$WORK/probe.lexe:/incoming/probe.lexe:ro" \
  -v "$WORK/probe.sha256:/incoming/probe.sha256:ro" \
  "$RUNTIME_IMAGE" sh -eu -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends bubblewrap ca-certificates >/dev/null
    echo "  old runtime: glibc $(getconf GNU_LIBC_VERSION | awk "{print \$2}")"

    # The artifact arrived UNCHANGED.
    GOT=$(sha256sum /incoming/probe.lexe | awk "{print \$1}")
    WANT=$(cat /incoming/probe.sha256)
    [ "$GOT" = "$WANT" ] || { echo "  CHECKSUM MISMATCH: $GOT != $WANT"; exit 1; }
    echo "  received checksum matches the built artifact ($GOT)"

    export LEXE_HOME=/root/.lexe
    lexe install /incoming/probe.lexe --yes --trust >/tmp/install.log 2>&1 \
      || { cat /tmp/install.log; exit 1; }
    echo "  installed."

    # Two launches under the sandbox; the persistent counter must advance.
    lexe run '"$APP_ID"' >/tmp/run1.log 2>&1 || { cat /tmp/run1.log; exit 1; }
    lexe run '"$APP_ID"' >/tmp/run2.log 2>&1 || { cat /tmp/run2.log; exit 1; }
    echo "---- launch 1 ----"; sed "s/^/    /" /tmp/run1.log
    echo "---- launch 2 ----"; sed "s/^/    /" /tmp/run2.log
    grep -q "status:        OK" /tmp/run1.log || { echo "  app did not report OK"; exit 1; }
    grep -q "launch count:  1" /tmp/run1.log || { echo "  first launch count wrong"; exit 1; }
    grep -q "launch count:  2" /tmp/run2.log || { echo "  persistent data did not survive"; exit 1; }
  '
ok "the unchanged artifact installed and launched under isolation on the old host"
ok "persistent app data survived across launches (counter 1 -> 2)"

# -----------------------------------------------------------------------------
step "Proof complete"
cat <<SUMMARY
  Newer-host build (glibc 2.39)  -> verdict $NATIVE_VERDICT (needs $NATIVE_GLIBC)  [REJECTED]
      ... and that binary truly fails to load on glibc 2.31 (GLIBC_2.34 not found)
  Sysroot build    (glibc 2.31)  -> verdict $CONF_VERDICT (needs $CONF_GLIBC)  [CONFORMANT]
  Signed artifact  probe.lexe    -> sha256 $BUILT_SHA
  Installed + launched TWICE on a fresh $RUNTIME_IMAGE under bubblewrap isolation,
  checksum unchanged end to end, persistent data intact.

  The build host did not become the compatibility target: the same source is
  portable ONLY when built to the published Core 1 contract, and the runtime
  enforces that with a typed verdict before the artifact is ever trusted.
SUMMARY

#!/usr/bin/env bash
# tests/lifecycle/lib.sh — helpers shared by the lifecycle scripts.
#
# Sourced AFTER tests/acceptance/lib.sh, whose reporting, scratch LEXE_HOME and
# headless guard these reuse. What this adds is the ability to produce several
# signed versions of one application cheaply, and a single place that answers the
# question every interruption test ends with:
#
#     is this installation coherent?
#
# Coherence is checked by CONSEQUENCE, never by reading .LEXE's own bookkeeping
# and agreeing with it. An installation is coherent when the runtime's view and
# the filesystem agree, and when the application either launches or is honestly
# absent. A state that reports an application the disk does not have — or has an
# application the runtime will not admit to — is the ambiguous half-applied state
# the transactional invariant exists to forbid.

LC_APP_ID="org.lexe.lifecycle.subject"
# The entrypoint as the MANIFEST declares it, relative to payload/.
LC_ENTRY="bin/subject"

# Where that entrypoint actually lands once installed.
#
# Extraction strips the `payload/` prefix, so the installed path is
# versions/<version>/<entrypoint.executable> and NOT
# versions/<version>/payload/<entrypoint.executable>. Worth a function rather
# than a string each caller builds: the first draft of these scripts built it by
# hand with the payload/ prefix still in it, and every check that touched the
# installed binary silently tested a path that could not exist.
lc_installed_entry() {
    printf '%s/apps/%s/versions/%s/%s' "$LEXE_HOME" "$LC_APP_ID" "$1" "$LC_ENTRY"
}

lc_version_dir() {
    printf '%s/apps/%s/versions/%s' "$LEXE_HOME" "$LC_APP_ID" "$1"
}

# A payload that reports its own version, so "which version is running" is
# answered by the RUNNING PROGRAM rather than by the registry. A test that asks
# the registry which version is current and then believes it cannot detect a
# registry that is wrong.
lc_write_project() {
    local dir="$1" version="$2"
    mkdir -p "$dir/src" "$dir/payload/bin"
    cat > "$dir/src/main.c" <<C_SOURCE
/* lifecycle subject — prints its own version and notes every start.
 *
 * Built once per version under test. It writes into LEXE_APP_DATA before doing
 * anything else, so a launch is provable from the private data root even if the
 * process is killed immediately afterwards. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *data = getenv("LEXE_APP_DATA");
    if (data != NULL && data[0] != '\0') {
        char path[2048];
        snprintf(path, sizeof path, "%s/starts.log", data);
        FILE *log = fopen(path, "a");
        if (log != NULL) {
            fprintf(log, "$version\n");
            fclose(log);
        }
    }
    printf("subject version $version\n");
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--sleep") == 0 && i + 1 < argc) {
            /* Stay alive so a test can act on a RUNNING application. */
            fflush(stdout);
            long seconds = strtol(argv[i + 1], NULL, 10);
            if (seconds > 120) seconds = 120;
            for (long s = 0; s < seconds; ++s) {
                struct timespec ts = {1, 0};
                nanosleep(&ts, NULL);
            }
        }
    }
    return 0;
}
C_SOURCE
    cat > "$dir/lexe.json" <<MANIFEST
{
  "lexeVersion": "0.1",
  "id": "$LC_APP_ID",
  "name": "Lifecycle Subject",
  "version": "$version",
  "publisher": { "name": "Lexe Tests", "publicKey": "AUTO" },
  "role": "application",
  "applicationType": "native",
  "architectures": ["x86_64"],
  "entrypoint": { "executable": "$LC_ENTRY", "arguments": [] },
  "execution": { "missionCritical": false, "allowedChains": ["native"] },
  "launch": { "mode": "console", "singleInstance": false },
  "install": { "scope": "user", "mode": "bundled" },
  "integration": { "desktopEntry": true, "categories": ["Utility"] },
  "permissions": []
}
MANIFEST
}

# lc_build_version <version> -> echoes the package path
#
# Builds and signs one version with the SAME key every time: an update that
# changed the signing key would be a key-rotation test, not an update test, and
# the runtime would (correctly) refuse it.
lc_build_version() {
    local version="$1"
    local dir="$ACC_ROOT/work/v$version"
    local package="$ACC_ROOT/work/subject-$version.lexe"
    [[ -f "$package" ]] && { printf '%s' "$package"; return 0; }

    lc_write_project "$dir" "$version"
    if ! cc -O2 -Wall -o "$dir/payload/$LC_ENTRY" "$dir/src/main.c" \
            >"$ACC_ROOT/work/cc-$version.log" 2>&1; then
        printf 'lifecycle: could not compile the subject payload\n' >&2
        sed 's/^/    /' "$ACC_ROOT/work/cc-$version.log" >&2
        return 1
    fi
    if [[ ! -f "$LC_KEY" ]]; then
        "$LEXE" keygen "$LC_KEY" >/dev/null || return 1
    fi
    if ! "$LEXE" build "$dir" -o "$package" --key "$LC_KEY" \
            >"$ACC_ROOT/work/build-$version.log" 2>&1; then
        printf 'lifecycle: could not package version %s\n' "$version" >&2
        sed 's/^/    /' "$ACC_ROOT/work/build-$version.log" >&2
        return 1
    fi
    printf '%s' "$package"
}

lc_setup() {
    acc_scratch_home
    LC_KEY="$ACC_ROOT/work/key.json"
    mkdir -p "$ACC_ROOT/work"
}

# ---------------------------------------------------------------- observation

lc_current_version() {
    acc_json "$(acc_installation_for "$LC_APP_ID")" 'd.get("version", "")' \
        2>/dev/null || true
}

lc_is_installed() {
    "$LEXE" list 2>/dev/null | grep -q "$LC_APP_ID"
}

# What the RUNNING program says it is, which is the only answer that cannot be
# wrong about itself.
lc_running_version() {
    local out
    out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)" || return 1
    printf '%s' "$out" | sed -n 's/^subject version \(.*\)$/\1/p' | tail -1
}

lc_starts_logged() {
    local log="$LEXE_HOME/data/$LC_APP_ID/starts.log"
    [[ -f "$log" ]] && wc -l < "$log" | tr -d ' ' || echo 0
}

# lc_complete_install <version> <package> -> 0 when the application ends up
# installed and working at <version>
#
# What "retry the interrupted operation" actually means. Installing a version
# that is ALREADY current is refused on purpose -- "already installed and
# current; use `lexe repair`" -- so a retry that simply re-runs install would
# report failure for a state that is perfectly fine. Which of the two paths
# applies depends on whether the interruption landed before or after promotion,
# and that is exactly what a test must not assume.
lc_complete_install() {
    local version="$1" package="$2"
    if [[ "$(lc_current_version)" == "$version" ]]; then
        # Already there: the right completion is to make sure its FILES are
        # whole, which is what repair is for.
        "$LEXE" repair "$LC_APP_ID" >/dev/null 2>&1 || return 1
    else
        "$LEXE" install "$package" --yes --trust >/dev/null 2>&1 || return 1
    fi
    [[ "$(lc_current_version)" == "$version" ]] || return 1
    [[ "$(lc_running_version)" == "$version" ]] || return 1
    return 0
}

# ---------------------------------------------------------------- the invariant

# lc_assert_coherent <label>
#
# The transactional invariant, checked from the outside. After ANY operation --
# completed, failed, or killed halfway -- exactly one of these must hold:
#
#   * the application is absent: `lexe list` does not name it, and no version
#     directory claims to be current; or
#   * the application is present AND launchable, and the version the runtime
#     reports is the version the program prints.
#
# Anything else is the ambiguous state the invariant forbids: an entry that
# cannot run, a current version with no directory, a directory with no record.
lc_assert_coherent() {
    local label="$1"
    local listed="absent"
    lc_is_installed && listed="present"
    local recorded; recorded="$(lc_current_version)"

    if [[ "$listed" == "absent" ]]; then
        # Nothing may still claim to be installed.
        if [[ -n "$recorded" ]]; then
            fail "$label: coherent" \
                "lexe list does not name the application, but installation.json" \
                "still records version \"$recorded\" as current"
            return 1
        fi
        pass "$label: coherent (absent, and nothing claims otherwise)"
        return 0
    fi

    if [[ -z "$recorded" ]]; then
        fail "$label: coherent" \
            "the application is listed as installed but no current version is recorded"
        return 1
    fi
    if [[ ! -d "$LEXE_HOME/apps/$LC_APP_ID/versions/$recorded" ]]; then
        fail "$label: coherent" \
            "version \"$recorded\" is recorded as current but its directory does not exist"
        return 1
    fi

    local ran; ran="$(lc_running_version)"
    if [[ -z "$ran" ]]; then
        fail "$label: coherent" \
            "recorded as installed at version \"$recorded\" but it will not launch"
        return 1
    fi
    if [[ "$ran" != "$recorded" ]]; then
        fail "$label: coherent" \
            "the registry says \"$recorded\" but the program that ran says \"$ran\""
        return 1
    fi
    pass "$label: coherent (installed at $recorded, and that is what runs)"
    return 0
}

# Kill `lexe` as soon as it reaches a given point in its own output.
#
# Racing a fixed sleep against an install is how an interruption test becomes
# flaky: on a fast machine the operation finishes first and the test proves
# nothing, while reporting success. Waiting for the operation to SAY where it is
# makes the interruption land in the same phase every run.
#
# lc_kill_at <pattern> <signal> -- <lexe args...>
lc_kill_at() {
    local pattern="$1" signal="$2"; shift 2
    [[ "${1:-}" == "--" ]] && shift
    local log="$ACC_ROOT/work/interrupt.log"
    : > "$log"

    "$LEXE" "$@" >"$log" 2>&1 &
    local pid=$!
    local waited=0 hit=0
    while [[ $waited -lt 600 ]]; do          # up to 60s
        if grep -qF "$pattern" "$log" 2>/dev/null; then hit=1; break; fi
        kill -0 "$pid" 2>/dev/null || break  # it finished before we could act
        sleep 0.1
        waited=$((waited + 1))
    done
    if [[ $hit -eq 1 ]]; then
        # The whole process group: the operation may have children (bwrap, a
        # compiler) and killing only the parent leaves them running.
        kill "-$signal" "$pid" 2>/dev/null
        pkill -"$signal" -P "$pid" 2>/dev/null
    fi
    wait "$pid" 2>/dev/null
    LC_INTERRUPT_HIT=$hit
    LC_INTERRUPT_LOG="$log"
    return 0
}

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

# -F and --, so the id is matched as literal text rather than as a regular
# expression: a dot in "org.lexe.lifecycle.subject" otherwise matches any
# character, and an id that happened to start with "-" would be read as a flag.
lc_is_installed() {
    [[ -n "$LC_APP_ID" ]] || return 1
    "$LEXE" list 2>/dev/null | grep -qF -- "$LC_APP_ID"
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
# It also SAYS WHICH STEP FAILED, in LC_COMPLETE_DETAIL. It used to return a
# bare 0/1 into `acc_true "$(lc_complete_install ...; echo $?)"`, so a failure
# printed "the install can be completed after being interrupted" and not one
# word about which of the four things it does went wrong -- an assertion whose
# own report cannot distinguish "the retry was refused" from "the retry worked
# and the program then would not run". Note also that calling it inside `$(...)`
# put it in a SUBSHELL, so nothing it learned could ever reach the caller; the
# call sites now run it directly and read the variable.
lc_complete_install() {
    local version="$1" package="$2" out=""
    LC_COMPLETE_DETAIL=""
    if [[ "$(lc_current_version)" == "$version" ]]; then
        # Already there: the right completion is to make sure its FILES are
        # whole, which is what repair is for.
        if ! out="$("$LEXE" repair "$LC_APP_ID" 2>&1)"; then
            LC_COMPLETE_DETAIL="\`lexe repair\` failed: $out"
            return 1
        fi
    else
        out="$("$LEXE" install "$package" --yes --trust 2>&1)"
        local st=$?
        # Exactly 0. This used to accept 6 as well, and the reason it gave was
        # true of the runtime at the time: installation.json is read BEFORE this
        # invocation, an interrupted install leaves a pending transaction, and
        # the next `lexe install` rolls it forward first -- after which it
        # reported exit 6, "already installed and current".
        #
        # 45704e1 decided that report was the defect: exit 6 means the requested
        # state ALREADY held and this call did nothing (docs/ERRORS.md §6), and
        # a call that healed an interrupted install did something. It now
        # returns 0. Still accepting 6 here kept the old misreport legal in the
        # one lane built to provoke it, so a regression of 45704e1 would have
        # passed through this suite unnoticed.
        #
        # This branch is only reached when the recorded version is NOT the
        # target, so neither route -- heal forward, or install normally -- has a
        # legitimate 6. The deterministic observer is tests/test_install_reporting.cpp;
        # this one fires only on runs where the kill lands after promotion.
        if [[ $st -ne 0 ]]; then
            LC_COMPLETE_DETAIL="re-running \`lexe install\` failed (exit $st): $out"
            return 1
        fi
    fi
    local recorded; recorded="$(lc_current_version)"
    if [[ "$recorded" != "$version" ]]; then
        LC_COMPLETE_DETAIL="the operation reported success but the current version is \"$recorded\", not $version"
        return 1
    fi
    local ran; ran="$(lc_running_version)"
    if [[ "$ran" != "$version" ]]; then
        LC_COMPLETE_DETAIL="registry says $version but the program that ran says \"$ran\""
        return 1
    fi
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

    # One state in which an installed application legitimately does not launch:
    # an UNFINISHED PURGE (a journal at apps/.removing/<id>.purge). The user asked
    # .LEXE to forget the application, so the launch is refused (exit 6) until
    # the purge finishes. FORMAT-0.1 §9.2 allows exactly this -- an installed
    # application "MUST be launchable, or MUST report honestly" -- and what it
    # forbids is still checked here, more strictly than for the ordinary case:
    # every file intact (no half-removal), the refusal is 6 and NAMES the purge,
    # and nothing executed. Every other installed state still has to RUN.
    if [[ -f "$LEXE_HOME/apps/.removing/$LC_APP_ID.purge" ]]; then
        local entry; entry="$(lc_installed_entry "$recorded")"
        if [[ ! -x "$entry" ]]; then
            fail "$label: coherent" \
                "installed at \"$recorded\" mid-purge, but its entrypoint is missing" \
                "or not executable: a purge must not half-remove an installation"
            return 1
        fi
        local starts_before out rc
        starts_before="$(lc_starts_logged)"
        out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)"; rc=$?
        if [[ "$rc" != "6" || "$out" != *"interrupted purge"* ]]; then
            fail "$label: coherent" \
                "installed at \"$recorded\" mid-purge, and the launch was not an" \
                "honest refusal (wanted exit 6 naming the purge; got $rc):" "$out"
            return 1
        fi
        if [[ "$(lc_starts_logged)" != "$starts_before" ]]; then
            fail "$label: coherent" "the refused launch executed the application"
            return 1
        fi
        pass "$label: coherent (installed at $recorded, files intact; launch honestly refused while a purge is unfinished)"
        return 0
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

# Kill `lexe` as soon as the operation reaches a given point.
#
# Racing a fixed sleep against an install is how an interruption test becomes
# flaky: on a fast machine the operation finishes first and the test proves
# nothing, while reporting success. Waiting for the operation to reach an
# OBSERVABLE point makes the interruption land in the same phase every run.
#
#     lc_kill_at <trigger> <signal> -- <lexe args...>
#
# <trigger> is one of
#
#     text:<substring>   once <substring> appears in the operation's own output
#     path:<glob>        once some path matching <glob> exists
#     gone:<glob>        once no path matching <glob> exists any more
#
# WHY THERE IS MORE THAN text:. Every caller used to pass the empty string.
# `grep -qF "" file` matches any line whatsoever, so "kill at phase X" actually
# meant "kill at the first byte of output, whatever it says" — a tautology
# wearing a phase's clothes. And it is worse than that here: `lexe install`
# prints nothing at all until it is finished, and the one line it then prints is
# "Installed <name> <version>". So the empty trigger waited for the operation to
# ANNOUNCE ITS OWN COMPLETION and then killed a process that had already done
# the work. Every "interrupted" case in 02_interrupted.sh was an ordinary
# completed operation with a signal sent to its corpse.
#
# path:/gone: exist because of that: an operation that says nothing mid-flight
# can still be caught by what it is doing to the disk.
#
# The poll does NOT sleep on the hot path. One install of the lifecycle subject
# takes about 35ms end to end, and a 0.1s poll cannot land inside 35ms — it can
# only ever observe the finished state. It backs off to a sleep once the
# operation is plainly long-running.
#
# The result is reported through LC_INTERRUPT_HIT, which must be read by
# lc_interrupt_report. It was set here and read by nothing for the whole life of
# this file: a value no observer consumes is not a signal, and the suite could
# interrupt nothing at all, every run, and print exactly the same greens.
lc_kill_at() {
    local trigger="$1" signal="$2"; shift 2
    [[ "${1:-}" == "--" ]] && shift

    LC_INTERRUPT_HIT=0
    LC_INTERRUPT_SPINS=0
    LC_INTERRUPT_TRIGGER="$trigger"
    LC_INTERRUPT_LOG="$ACC_ROOT/work/interrupt.log"

    local kind="${trigger%%:*}" want="${trigger#*:}"
    if [[ -z "$trigger" || "$trigger" != *:* || -z "$want" ]]; then
        fail "lc_kill_at: unusable trigger \"$trigger\"" \
            "a trigger must be text:<substring>, path:<glob> or gone:<glob>." \
            "An empty one matches everything and interrupts nothing."
        return 2
    fi
    case "$kind" in
        text|path|gone) ;;
        *) fail "lc_kill_at: unknown trigger kind \"$kind\"" \
               "expected text:, path: or gone:"
           return 2 ;;
    esac

    local log="$LC_INTERRUPT_LOG"
    : > "$log"

    "$LEXE" "$@" >"$log" 2>&1 &
    local pid=$!
    local hit=0 spins=0
    while :; do
        case "$kind" in
            text) grep -qF -- "$want" "$log" 2>/dev/null && { hit=1; break; } ;;
            path) compgen -G "$want" >/dev/null 2>&1 && { hit=1; break; } ;;
            gone) compgen -G "$want" >/dev/null 2>&1 || { hit=1; break; } ;;
        esac
        kill -0 "$pid" 2>/dev/null || break  # it finished before we could act
        spins=$((spins + 1))
        [[ $spins -gt 400000 ]] && break
        if [[ $((spins % 4000)) -eq 0 ]]; then sleep 0.05; fi
    done
    if [[ $hit -eq 1 ]]; then
        # The whole process group: the operation may have children (bwrap, a
        # compiler) and killing only the parent leaves them running.
        kill "-$signal" "$pid" 2>/dev/null
        pkill -"$signal" -P "$pid" 2>/dev/null
    fi
    wait "$pid" 2>/dev/null
    LC_INTERRUPT_STATUS=$?
    LC_INTERRUPT_HIT=$hit
    LC_INTERRUPT_SPINS=$spins
    return 0
}

# lc_interrupt_report <label>
#
# The observer lc_kill_at never had. It turns "did anything actually get
# interrupted?" into a reported outcome instead of an unread variable.
#
# A run that did not interrupt anything is BLOCKED, not PASS and not FAIL: the
# coherence assertion that follows is still meaningful, but it is then a
# statement about an ordinary completed operation, and the interruption case
# this suite exists for was not exercised on this machine. BLOCKED is what this
# harness calls a claim that is still unproven, and that is exactly what it is.
lc_interrupt_report() {
    local label="$1"
    if [[ "${LC_INTERRUPT_HIT:-0}" == "1" ]]; then
        pass "$label: the ${LC_INTERRUPT_TRIGGER%%:*} trigger fired and the signal landed mid-operation"
        return 0
    fi
    blocked "$label: nothing was interrupted" \
        "the operation reached its end before the trigger" \
        "\"${LC_INTERRUPT_TRIGGER:-<unset>}\" fired (${LC_INTERRUPT_SPINS:-0} polls)." \
        "Whatever the coherence check below reports, it reports it about an" \
        "operation that completed normally -- not about an interrupted one."
    return 1
}

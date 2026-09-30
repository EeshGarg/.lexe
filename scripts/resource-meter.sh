#!/usr/bin/env bash
# scripts/resource-meter.sh — run a command and measure what it actually cost.
#
#   scripts/resource-meter.sh [-i SECS] [-l LABEL] -- <command> [args...]
#
# The resource policy in docs/TESTING.md §10 sets hard limits: <=50% sustained
# host CPU, <=4 GiB for test/build infrastructure, and no sustained storage
# saturation. A limit nobody measures is a wish, and this project's standing
# rule is that a capability is a claim until something demonstrates it -- which
# applies to claims about our own resource use as much as to claims about the
# product.
#
# So this reports PEAK total RSS and CPU across the command's whole process
# tree, not just the parent. `/usr/bin/time -v` is not enough here: for `make`
# or `ninja` it reports the largest SINGLE child, and the thing the policy
# bounds is the SUM of a dozen concurrent compilers.
#
# Selection is by session id, not by walking parent links. A compiler that
# exits between two samples is missed either way, but a process that
# re-parents to init (which happens when a build driver is killed) stays in the
# session and stays counted -- whereas a parent-walk would lose it and
# under-report exactly when a run is going wrong.
#
# Output goes to stderr so it does not contaminate the measured command's
# stdout; --json writes a machine-readable line to the path given.
#
# Sampling is a floor, not a ceiling: a spike shorter than the interval is
# invisible. The default 0.5s is chosen against compiler lifetimes of seconds.
# It never claims a peak it did not observe, and it says how many samples it
# took so a suspiciously small number is visible rather than silent.

set -uo pipefail

INTERVAL=0.5
LABEL=""
JSON_OUT=""

usage() {
    cat >&2 <<'EOF'
usage: scripts/resource-meter.sh [-i SECS] [-l LABEL] [-j JSON_PATH] -- <command> [args...]
  -i  sample interval in seconds (default 0.5)
  -l  label for the report
  -j  also write a JSON object to this path
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i) INTERVAL="${2:-}"; shift 2 ;;
        -l) LABEL="${2:-}"; shift 2 ;;
        -j) JSON_OUT="${2:-}"; shift 2 ;;
        --) shift; break ;;
        *)  usage ;;
    esac
done
[[ $# -gt 0 ]] || usage

CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"
NCPU="$(nproc 2>/dev/null || echo 1)"
[[ "$NCPU" -gt 0 ]] || NCPU=1

# Run it directly and sample its process TREE.
#
# An earlier version used `setsid` and selected by session id, which is tidier
# in principle and wrong in practice: `setsid` forks when its caller is already
# a process group leader, so `$!` was a process that exited immediately, the
# sampler measured an empty set, and the run reported a peak of 0 MiB. That
# reads exactly like a cheap run. It was caught only because the "nothing was
# sampled" guard below refuses to let a zero pass as a measurement -- which is
# the entire reason that guard exists.
#
# The honest limitation of a tree walk, stated rather than papered over: a
# process that re-parents to init leaves the tree and stops being counted. For
# build and test drivers, which wait on their children, that does not normally
# happen; for a daemon that deliberately detaches, this tool will under-report
# and should not be the only observer.
"$@" &
child=$!

peak_rss_kb=0
peak_cpu_pct=0
samples=0

while kill -0 "$child" 2>/dev/null; do
    # One ps per sample; awk computes the transitive closure of descendants of
    # $child by iterating to a fixpoint, because `ps` output is in no useful
    # order and a child can appear before its parent.
    read -r sum_rss sum_jiffies < <(
        ps -eo pid=,ppid=,rss= 2>/dev/null |
        awk -v root="$child" '
            { par[$1]=$2; rss[$1]=$3; ord[++n]=$1 }
            END {
                mine[root]=1
                changed=1
                while (changed) {
                    changed=0
                    for (i=1;i<=n;i++) {
                        p=ord[i]
                        if (!mine[p] && mine[par[p]]) { mine[p]=1; changed=1 }
                    }
                }
                r=0; j=0
                for (i=1;i<=n;i++) {
                    p=ord[i]
                    if (!mine[p]) continue
                    r += rss[p]
                    # utime+stime in clock ticks, fields 14 and 15 of
                    # /proc/<pid>/stat. Read here rather than taking ps -o
                    # pcpu, which is the process LIFETIME AVERAGE: summing
                    # that across many short-lived compilers reported 107.1%
                    # of 24 CPUs, which is not a possible number. CPU used
                    # between two samples is a difference of counters, not a
                    # sum of averages.
                    f = "/proc/" p "/stat"
                    if ((getline line < f) > 0) {
                        # comm can contain spaces and parentheses; everything
                        # after the last ")" is positionally reliable.
                        k = index(line, ")")
                        rest = substr(line, k + 2)
                        m = split(rest, fld, " ")
                        # rest[1] is state, so utime is 12 and stime 13 here.
                        if (m >= 13) j += fld[12] + fld[13]
                    }
                    close(f)
                }
                printf "%d %d\n", r, j
            }'
    )
    # Instantaneous tree utilization = ticks consumed between samples, over
    # ticks available in that wall time across all CPUs.
    sum_cpu=0
    if [[ -n "${prev_jiffies:-}" && -n "${sum_jiffies:-}" ]]; then
        delta=$(( sum_jiffies - prev_jiffies ))
        (( delta < 0 )) && delta=0
        # tenths of a percent of ONE cpu, to match the reporting below
        avail=$(awk -v i="$INTERVAL" -v hz="$CLK_TCK" 'BEGIN{printf "%d", i*hz}')
        (( avail > 0 )) && sum_cpu=$(( delta * 1000 / avail ))
    fi
    prev_jiffies="${sum_jiffies:-0}"
    if [[ -n "${sum_rss:-}" && "$sum_rss" -gt 0 ]]; then
        (( sum_rss > peak_rss_kb )) && peak_rss_kb=$sum_rss
        (( sum_cpu > peak_cpu_pct )) && peak_cpu_pct=$sum_cpu
        samples=$((samples + 1))
    fi
    sleep "$INTERVAL"
done

wait "$child"; rc=$?

# peak_cpu_pct is in tenths of a percent-of-one-core, summed across the tree.
# Host utilization = that / NCPU. Both are reported: the first says how much
# work was in flight, the second is what the policy actually bounds.
host_cpu_tenths=$(( peak_cpu_pct / NCPU ))
peak_rss_mib=$(( peak_rss_kb / 1024 ))
budget_mib=4096

printf '\n[resource-meter] %s\n' "${LABEL:-command}" >&2
printf '  exit            %d\n' "$rc" >&2
printf '  samples         %d (every %ss)\n' "$samples" "$INTERVAL" >&2
printf '  peak tree RSS   %d MiB   (budget %d MiB, %d%% used)\n' \
    "$peak_rss_mib" "$budget_mib" "$(( peak_rss_mib * 100 / budget_mib ))" >&2
printf '  peak host CPU   %d.%d%% of %d logical CPUs\n' \
    "$(( host_cpu_tenths / 10 ))" "$(( host_cpu_tenths % 10 ))" "$NCPU" >&2

if [[ "$samples" -eq 0 ]]; then
    printf '  NOTE: nothing was sampled -- this is not evidence of a cheap run\n' >&2
elif [[ "$peak_rss_mib" -gt "$budget_mib" ]]; then
    printf '  OVER BUDGET: RSS exceeded the 4 GiB testing budget\n' >&2
elif [[ "$host_cpu_tenths" -gt 500 ]]; then
    printf '  OVER BUDGET: sustained-CPU target of 50%% was exceeded at peak\n' >&2
fi

if [[ -n "$JSON_OUT" ]]; then
    printf '{"label":"%s","exit":%d,"samples":%d,"interval_s":%s,"peak_rss_mib":%d,"peak_host_cpu_pct":%d.%d,"logical_cpus":%d,"budget_mib":%d}\n' \
        "${LABEL:-command}" "$rc" "$samples" "$INTERVAL" "$peak_rss_mib" \
        "$(( host_cpu_tenths / 10 ))" "$(( host_cpu_tenths % 10 ))" "$NCPU" "$budget_mib" \
        > "$JSON_OUT"
fi

exit "$rc"

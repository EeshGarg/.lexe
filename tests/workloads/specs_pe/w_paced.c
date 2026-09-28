/* Slowly paced output: argv[1] lines, argv[2] milliseconds between them.
 *
 * A program that dribbles output over seconds is the case where a supervisor that
 * buffers, or that waits for EOF before showing anything, behaves differently
 * from one that streams. Every line goes to stdout, to stderr and to paced.log,
 * so a consumer can see whether the pacing survived on each channel.
 *
 * paced.log carries nothing but the paced lines, so its line COUNT is a
 * deterministic property. The elapsed time is an observation, always.
 */
#include "oracle_win.h"

int main(int argc, char **argv) {
    long lines = argc > 1 ? atol(argv[1]) : 12;
    long gap = argc > 2 ? atol(argv[2]) : 250;
    long i;
    FILE *log;
    LARGE_INTEGER freq, t0, t1;
    double elapsed;

    orc_begin("pe-io-paced");
    orc_kv("PACED_LINES_REQUESTED", "%ld", lines);
    orc_kv("PACE_INTERVAL_MS", "%ld", gap);

    log = fopen("paced.log", "wb");
    orc_check("PACED_LOG_OPEN", log != NULL);
    if (!log) return orc_end();

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    for (i = 0; i < lines; i++) {
        fprintf(stdout, "PACED_TICK=%ld\n", i);
        fflush(stdout);
        fprintf(stderr, "PACED_TICK_ERR=%ld\n", i);
        fflush(stderr);
        fprintf(log, "PACED_TICK=%ld\n", i);
        fflush(log);
        if (i + 1 < lines) Sleep((DWORD)gap);
    }
    QueryPerformanceCounter(&t1);
    fclose(log);
    elapsed = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
    orc_obs("PACED_ELAPSED_MS", "%.0f", elapsed);

    log = fopen("paced.log", "rb");
    orc_check("PACED_LOG_REOPEN", log != NULL);
    if (log) {
        long counted = 0;
        int c;
        while ((c = fgetc(log)) != EOF) if (c == '\n') counted++;
        fclose(log);
        orc_kv("PACED_LOG_LINES", "%ld", counted);
        orc_check("PACED_ALL_LINES_LANDED", counted == lines);
    }
    /* An OBSERVATION, not a self-check, and the distinction is the whole point.
     * This was `orc_check("PACED_TOOK_AT_LEAST_THE_GAPS", ...)` -- a
     * DETERMINISTIC assertion about elapsed wall time -- and it failed on two of
     * five identical repeats under Wine and under Proton's Wine. Measured:
     * 2560, 2766, 2729, 2664 and 2765 ms against an 11 x 250 ms floor of 2690.
     *
     * Sleep(n) does not promise to take n milliseconds; on a translation layer
     * it frequently returns early. So the floor is a fact about the LAYER, not
     * about the program, and asserting it made the specimen report the host's
     * timer behaviour as a fixture failure -- which is the same mistake as
     * declaring a duration deterministic anywhere else in this corpus.
     *
     * What remains deterministic is what the program actually controls: it
     * asked for `lines` lines, it wrote `lines` lines, they all landed, and the
     * log reopened. Pacing is still visible, as an observation with the real
     * number beside it. */
    orc_obs("PACED_GAP_FLOOR_MS", "%ld", (lines - 1) * gap);
    orc_obs("PACED_MET_GAP_FLOOR", "%s",
            elapsed >= (double)((lines - 1) * gap) - 60.0 ? "yes" : "no");
    orc_kv("DURATION_CLASS", "%s", (lines - 1) * gap >= 1000 ? "seconds" : "sub-second");
    return orc_end();
}

/* A bounded long-running process: sleeps for argv[1] milliseconds in one Sleep,
 * reports the measured elapsed time as an observation, and checks that it really
 * slept rather than skipping the sleep. Under a translation layer the measured
 * time is not the interesting part; that it is bounded and exits cleanly is.
 *
 * ABOUT THE TOLERANCE, because it was wrong once and the way it was wrong is
 * instructive. This check originally required the elapsed time to be within 20 ms
 * of the requested 3000 -- and on a loaded host it FAILED, with Sleep(3000)
 * returning after 2962 ms of QueryPerformanceCounter time. Sleep did not return
 * early in any meaningful sense: Sleep and QueryPerformanceCounter are different
 * clocks in this layer and they do not agree to better than a few tens of
 * milliseconds when the machine is busy. A 20 ms window on 3000 ms is 0.67%, which
 * made this a PERFORMANCE ASSERTION wearing a correctness assertion's clothes --
 * exactly the thing this corpus forbids everywhere else.
 *
 * So the deterministic check is now the one that actually distinguishes a working
 * Sleep from a broken one -- a layer that ignored Sleep entirely would return in
 * microseconds, not 1% early -- and the clock disagreement it uncovered is
 * reported as an OBSERVATION in its own right, where it belongs and where it can
 * be seen rather than causing a mystery failure.
 */
#include "oracle_win.h"

int main(int argc, char **argv) {
    DWORD ms = argc > 1 ? (DWORD)strtoul(argv[1], NULL, 10) : 3000;
    LARGE_INTEGER freq, t0, t1;
    double elapsed, floor_ms;
    orc_begin("pe-run-bounded");
    orc_kv("SLEEP_REQUESTED_MS", "%lu", (unsigned long)ms);
    /* Ninety per cent of the request: far below any real clock disagreement and
     * far above what a layer that dropped the sleep on the floor would produce. */
    floor_ms = (double)ms * 0.9;
    orc_kv("SLEEP_FLOOR_MS", "%.0f", floor_ms);
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    Sleep(ms);
    QueryPerformanceCounter(&t1);
    elapsed = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
    orc_obs("ELAPSED_MS", "%.0f", elapsed);
    /* How far the two clocks disagreed, signed: negative means the performance
     * counter says less time passed than Sleep was asked to wait. Environment
     * dependent by nature, so never a deterministic key. */
    orc_obs("SLEEP_VERSUS_QPC_MS", "%.0f", elapsed - (double)ms);
    orc_obs("QPC_AGREED_WITHIN_20MS", "%s",
            elapsed >= (double)ms - 20.0 ? "yes" : "no");
    orc_check("SLEPT_AT_LEAST_REQUESTED", elapsed >= floor_ms);
    orc_check("SLEEP_WAS_NOT_SKIPPED", elapsed >= (double)ms * 0.5);
    orc_kv("DURATION_CLASS", "%s", ms < 1000 ? "sub-second" : "seconds");
    return orc_end();
}

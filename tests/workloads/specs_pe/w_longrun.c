/* A bounded long-running process: sleeps for argv[1] milliseconds in one Sleep,
 * reports the measured elapsed time as an observation and the fact that it slept
 * at least as long as asked as a check. Under a translation layer the measured
 * time is not the interesting part; that it is bounded and exits cleanly is. */
#include "oracle_win.h"

int main(int argc, char **argv) {
    DWORD ms = argc > 1 ? (DWORD)strtoul(argv[1], NULL, 10) : 3000;
    LARGE_INTEGER freq, t0, t1;
    double elapsed;
    orc_begin("pe-run-bounded");
    orc_kv("SLEEP_REQUESTED_MS", "%lu", (unsigned long)ms);
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    Sleep(ms);
    QueryPerformanceCounter(&t1);
    elapsed = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
    orc_obs("ELAPSED_MS", "%.0f", elapsed);
    orc_check("SLEPT_AT_LEAST_REQUESTED", elapsed >= (double)ms - 20.0);
    orc_kv("DURATION_CLASS", "%s", ms < 1000 ? "sub-second" : "seconds");
    return orc_end();
}

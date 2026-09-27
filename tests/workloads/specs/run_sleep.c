/* A bounded run: sleeps for argv[1] milliseconds in one nanosleep, then reports
 * the measured elapsed time as an observation and the fact that it was at least
 * as long as requested as a check. */
#include "oracle.h"
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    long ms = argc > 1 ? atol(argv[1]) : 500;
    struct timespec req, t0, t1;
    double elapsed;
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-run-bounded");
    orc_kv("SLEEP_REQUESTED_MS", "%ld", ms);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&req, &req) != 0 && errno == EINTR) { }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed = (double)(t1.tv_sec - t0.tv_sec) * 1000.0
            + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
    orc_obs("ELAPSED_MS", "%.0f", elapsed);
    orc_check("SLEPT_AT_LEAST_REQUESTED", elapsed >= (double)ms - 5.0);
    orc_kv("DURATION_CLASS", "%s", ms < 1000 ? "sub-second" : "seconds");
    return orc_end();
}

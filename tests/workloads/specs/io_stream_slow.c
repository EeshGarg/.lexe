/* Output that arrives slowly, in bursts, with the stream held open throughout.
 *
 *   argv[1]  number of ticks          (required)
 *   argv[2]  milliseconds between them (required)
 *   argv[3]  milliseconds of silence AFTER the last tick, before exit (required)
 *
 * What this is for: a relay that waits on the wrong thing cannot be told apart
 * from a correct one by any amount of output delivered instantly. Three
 * distinguishable mistakes show up here and nowhere else:
 *
 *   * a reader that waits for the process to exit before reading anything at
 *     all still gets the right bytes -- but the arrival times recorded by a
 *     consumer show every tick landing at once;
 *   * a reader that treats a short read or a momentary EAGAIN as end-of-stream
 *     truncates at the first pause, and the digest fails;
 *   * a reader that waits on the child's exit rather than on end-of-stream
 *     hangs for the trailing silence, or stops before it.
 *
 * Each tick is a fixed-size chunk beginning with a plain ASCII marker
 * "TICK-nnnn " so a consumer can see WHICH tick it has, followed by
 * deterministic filler. The marker is deterministic; the timings are OBS_.
 */
#include "oracle.h"
#include "orc_bulk.h"
#include <time.h>

#define TICK_BYTES 32768u

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void sleep_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) { }
}

int main(int argc, char **argv) {
    static uint8_t buf[TICK_BYTES];
    orb_rng rng;
    orb_sha256 sha;
    char hex[65];
    long ticks, gap_ms, tail_ms, i;
    unsigned long long written = 0;
    double t0, t_first = 0.0, t_last = 0.0;

    orc_ebegin("linux-io-stream-slow");
    if (argc < 4) {
        fprintf(stderr, "USAGE=io_stream_slow <ticks> <gap_ms> <tail_ms>\nRESULT=FAIL\n");
        return 2;
    }
    ticks = strtol(argv[1], NULL, 10);
    gap_ms = strtol(argv[2], NULL, 10);
    tail_ms = strtol(argv[3], NULL, 10);
    fprintf(stderr, "SLOW_TICKS_REQUESTED=%ld\n", ticks);
    fprintf(stderr, "SLOW_GAP_MS=%ld\n", gap_ms);
    fprintf(stderr, "SLOW_TAIL_MS=%ld\n", tail_ms);
    fprintf(stderr, "SLOW_TICK_BYTES=%u\n", TICK_BYTES);

    orb_rng_init(&rng);
    orb_sha256_init(&sha);
    t0 = now_ms();
    for (i = 0; i < ticks; i++) {
        int n;
        if (i > 0) sleep_ms(gap_ms);
        orb_fill(&rng, buf, TICK_BYTES);
        /* Overwrite the first 16 bytes with the marker, AFTER filling, so the
         * marker is part of what the digest covers. */
        n = snprintf((char *)buf, 16, "TICK-%04ld ", i);
        if (n < 0 || n >= 16) { fprintf(stderr, "MARKER_FAILED=yes\nRESULT=FAIL\n"); return 1; }
        while (n < 15) buf[n++] = ' ';
        buf[15] = '\n';
        orb_sha256_update(&sha, buf, TICK_BYTES);
        if (orb_write_all(1, buf, TICK_BYTES) != 0) {
            fprintf(stderr, "WRITE_FAILED_AT_TICK=%ld\nRESULT=FAIL\n", i);
            return 1;
        }
        written += TICK_BYTES;
        if (i == 0) t_first = now_ms();
        t_last = now_ms();
        /* Progress on stderr as well, so a consumer watching either stream can
         * see the pacing and say which one it lost. */
        fprintf(stderr, "OBS_TICK_%04ld_MS=%.0f\n", i, t_last - t0);
    }
    orb_sha256_final(&sha, hex);
    fprintf(stderr, "SLOW_TICKS_WRITTEN=%ld\n", ticks);
    fprintf(stderr, "SLOW_BYTES=%llu\n", written);
    fprintf(stderr, "SLOW_SHA256=%s\n", hex);
    fprintf(stderr, "OBS_SPAN_MS=%.0f\n", t_last - t_first);

    /* Silence with both streams still open. Anything that mistakes a pause for
     * an end has already gone wrong by the time this returns. */
    sleep_ms(tail_ms);
    fprintf(stderr, "SLOW_TAIL_ELAPSED=yes\n");
    fprintf(stderr, "OBS_TOTAL_MS=%.0f\n", now_ms() - t0);
    fprintf(stderr, "RESULT=PASS\n");
    return 0;
}

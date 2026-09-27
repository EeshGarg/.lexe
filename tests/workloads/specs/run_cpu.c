/* A deterministic CPU-bound run: a fixed number of integer rounds producing a
 * fixed checksum. The result does not depend on the clock, so the specimen is
 * reproducible even though its duration is not. */
#include "oracle.h"
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    unsigned long rounds = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000000UL;
    unsigned long x = 0x243F6A8885A308D3UL, i;
    struct timespec t0, t1;
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-run-cpu-bound");
    orc_kv("ROUNDS", "%lu", rounds);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < rounds; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        x += i;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    orc_kv("CHECKSUM", "%016lx", x);
    orc_obs("ELAPSED_MS", "%.0f", (double)(t1.tv_sec - t0.tv_sec) * 1000.0
            + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6);
    orc_check("WORK_COMPLETED", i == rounds);
    return orc_end();
}
